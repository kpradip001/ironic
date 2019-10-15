#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
DRAC inspection interface
"""

from datetime import datetime
import json
import re

from ironic_lib import metrics_utils
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import units
import requests

from ironic.common import boot_modes
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import states
from ironic.common import utils
from ironic.drivers import base
from ironic.drivers.modules.drac import common as drac_common
from ironic.drivers.modules.redfish import inspect as redfish_inspect
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic.drivers import utils as drivers_utils
from ironic import objects

drac_exceptions = importutils.try_import('dracclient.exceptions')

LOG = logging.getLogger(__name__)

METRICS = metrics_utils.get_metrics_logger(__name__)

sushy = importutils.try_import('sushy')

if sushy:
    CPU_ARCH_MAP = {
        sushy.PROCESSOR_ARCH_x86: 'x86_64',
        sushy.PROCESSOR_ARCH_IA_64: 'ia64',
        sushy.PROCESSOR_ARCH_ARM: 'arm',
        sushy.PROCESSOR_ARCH_MIPS: 'mips',
        sushy.PROCESSOR_ARCH_OEM: 'oem'
    }

    BOOT_MODE_MAP = {
        sushy.BOOT_SOURCE_MODE_UEFI: boot_modes.UEFI,
        sushy.BOOT_SOURCE_MODE_BIOS: boot_modes.LEGACY_BIOS
    }

# System Configuration Tag Constant
_SYSTEM_CONFIG_TAG = '<SystemConfiguration Model'

# Time Out Constant
_TIMEOUT_SECONDS = 120

# Job Id Url Constant
_JOB_ID_URL = '/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/' \
              'EID_674_Manager.ExportSystemConfiguration'

# Xml Data Url Constant
_XML_DATA_URL = '/redfish/v1/TaskService/Tasks/'

# Mac Address Url Constant
_MAC_URL = '/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/'

# Payload Constant
_PAYLOAD = {'ExportFormat': 'XML', 'ShareParameters': {'Target': 'NIC'}}

# Headers Constant
_HEADERS = {'content-type': 'application/json'}

# Job Response Code Constant
_JOB_RESPONSE_CODE = 202


class DracRedfishInspect(redfish_inspect.RedfishInspect):
    """iDRAC Redfish interface for inspection-related actions.

    Presently, this class entirely defers to its base class, a generic,
    vendor-independent Redfish interface. Future resolution of Dell EMC-
    specific incompatibilities and introduction of vendor value added
    should be implemented by this class.
    """

    def inspect_hardware(self, task):
        """Inspect hardware to get the hardware properties.

        Inspects hardware to get the essential properties.
        It fails if any of the essential properties
        are not received from the node.

        :param task: a TaskManager instance.
        :raises: HardwareInspectionFailure if essential properties
                 could not be retrieved successfully.
        :returns: The resulting state of inspection.

        """
        node = task.node
        system = redfish_utils.get_system(node)

        # get the essential properties and update the node properties
        # with it.
        inspected_properties = node.properties

        if system.memory_summary and system.memory_summary.size_gib:
            inspected_properties['memory_mb'] = str(
                system.memory_summary.size_gib * units.Ki)

        if system.processors and system.processors.summary:
            cpus, arch = system.processors.summary
            if cpus:
                inspected_properties['cpus'] = cpus

            if arch:
                try:
                    inspected_properties['cpu_arch'] = CPU_ARCH_MAP[arch]

                except KeyError:
                    LOG.warning("Unknown CPU arch %(arch)s discovered "
                                "for node %(node)s", {'node': node.uuid,
                                                      'arch': arch})

        simple_storage_size = 0

        try:
            LOG.debug("Attempting to discover system simple storage size for "
                      "node %(node)s", {'node': node.uuid})
            if (system.simple_storage
                    and system.simple_storage.disks_sizes_bytes):
                simple_storage_size = [
                    size for size in system.simple_storage.disks_sizes_bytes
                    if size >= 4 * units.Gi
                ] or [0]

                simple_storage_size = simple_storage_size[0]

        except sushy.exceptions.SushyError as ex:
            LOG.debug("No simple storage information discovered "
                      "for node %(node)s: %(err)s", {'node': node.uuid,
                                                     'err': ex})

        storage_size = 0

        try:
            LOG.debug("Attempting to discover system storage volume size for "
                      "node %(node)s", {'node': node.uuid})
            if system.storage and system.storage.volumes_sizes_bytes:
                storage_size = [
                    size for size in system.storage.volumes_sizes_bytes
                    if size >= 4 * units.Gi
                ] or [0]

                storage_size = storage_size[0]

        except sushy.exceptions.SushyError as ex:
            LOG.debug("No storage volume information discovered "
                      "for node %(node)s: %(err)s", {'node': node.uuid,
                                                     'err': ex})

        try:
            if not storage_size:
                LOG.debug("Attempting to discover system storage drive size "
                          "for node %(node)s", {'node': node.uuid})
                if system.storage and system.storage.drives_sizes_bytes:
                    storage_size = [
                        size for size in system.storage.drives_sizes_bytes
                        if size >= 4 * units.Gi
                    ] or [0]

                    storage_size = storage_size[0]
        except sushy.exceptions.SushyError as ex:
            LOG.debug("No storage drive information discovered "
                      "for node %(node)s: %(err)s", {'node': node.uuid,
                                                     'err': ex})

        # NOTE(etingof): pick the smallest disk larger than 4G among available
        if simple_storage_size and storage_size:
            local_gb = min(simple_storage_size, storage_size)

        else:
            local_gb = max(simple_storage_size, storage_size)

        # Note(deray): Convert the received size to GiB and reduce the
        # value by 1 GB as consumers like Ironic requires the ``local_gb``
        # to be returned 1 less than actual size.
        local_gb = max(0, int(local_gb / units.Gi - 1))

        # TODO(etingof): should we respect root device hints here?

        if local_gb:
            inspected_properties['local_gb'] = str(local_gb)
        else:
            LOG.warning("Could not provide a valid storage size configured "
                        "for node %(node)s. Assuming this is a disk-less node",
                        {'node': node.uuid})
            inspected_properties['local_gb'] = '0'

        if system.boot.mode:
            if not drivers_utils.get_node_capability(node, 'boot_mode'):
                capabilities = utils.get_updated_capabilities(
                    inspected_properties.get('capabilities', ''),
                    {'boot_mode': BOOT_MODE_MAP[system.boot.mode]})

                inspected_properties['capabilities'] = capabilities

        valid_keys = self.ESSENTIAL_PROPERTIES
        missing_keys = valid_keys - set(inspected_properties)
        if missing_keys:
            error = (_('Failed to discover the following properties: '
                       '%(missing_keys)s on node %(node)s'),
                     {'missing_keys': ', '.join(missing_keys),
                      'node': node.uuid})
            raise exception.HardwareInspectionFailure(error=error)

        node.properties = inspected_properties
        node.save()

        LOG.debug("Node properties for %(node)s are updated as "
                  "%(properties)s", {'properties': inspected_properties,
                                     'node': node.uuid})

        pxe_dev_nics = self._get_pxe_dev_nics(task, system)
        if pxe_dev_nics is None:
            LOG.warning("No PXE enabled NIC was found for node "
                        "%(node_uuid)s.", {'node_uuid': node.uuid})

        if (system.ethernet_interfaces
                and system.ethernet_interfaces.summary):
            macs = system.ethernet_interfaces.summary

            # Create ports for the discovered NICs being in 'enabled' state
            enabled_macs = {nic_mac: nic_state
                            for nic_mac, nic_state in macs.items()
                            if nic_state == sushy.STATE_ENABLED}
            if enabled_macs:
                for k_v_pair in enabled_macs.items():
                    mac = k_v_pair[0]
                    port = objects.Port(task.context, address=mac,
                                        node_id=node.id,
                                        pxe_enabled=(mac in pxe_dev_nics))
                    try:
                        port.create()
                        LOG.info('Port created with MAC address %(mac)s '
                                 'for node %(node_uuid)s during inspection',
                                 {'mac': mac, 'node_uuid': node.uuid})
                    except exception.MACAlreadyExists:
                        LOG.warning("Port already exists for MAC address "
                                    "%(address)s for node %(node)s",
                                    {'address': mac, 'node': node.uuid})
            else:
                LOG.warning("Not attempting to create any port as no NICs "
                            "were discovered in 'enabled' state for node "
                            "%(node)s: %(mac_data)s",
                            {'mac_data': macs, 'node': node.uuid})
        else:
            LOG.warning("No NIC information discovered "
                        "for node %(node)s", {'node': node.uuid})

        return states.MANAGEABLE

    def _get_pxe_dev_nics(self, task, system):
        """Get a list of pxe device interfaces.

        :param task: a TaskManager instance.
        :param system: a Redfish System object that represents a node.
        :returns: Returns list of pxe device interfaces.
        """
        pxe_dev_nics = []
        pxe_params = ["PxeDev1EnDis", "PxeDev2EnDis",
                      "PxeDev3EnDis", "PxeDev4EnDis"]
        pxe_nics = ["PxeDev1Interface", "PxeDev2Interface",
                    "PxeDev3Interface", "PxeDev4Interface"]

        redfish_ip = task.node.driver_info.get('redfish_address')
        redfish_username = task.node.driver_info.get('redfish_username')
        redfish_password = task.node.driver_info.get('redfish_password')

        if system.boot.mode == 'uefi':
            for param, nic in zip(pxe_params, pxe_nics):
                if system.bios.attributes[param] == 'Enabled':
                    nic_id = system.bios.attributes[nic]
                    mac_response = requests.get('%s%s%s' % (
                        redfish_ip, _MAC_URL, nic_id), auth=(
                        redfish_username, redfish_password), verify=False)
                    mac_address = json.loads(mac_response.__dict__.get(
                        '_content')).get('MACAddress')
                    pxe_dev_nics.append(mac_address)

        elif system.boot.mode == 'bios':
            redfish_username = task.node.driver_info.get('redfish_username')
            redfish_password = task.node.driver_info.get('redfish_password')

            url = "%s%s" % (redfish_ip, _JOB_ID_URL)
            job_response = requests.post(url, data=json.dumps(
                _PAYLOAD), headers=_HEADERS, verify=False, auth=(
                redfish_username, redfish_password))

            if job_response.status_code != _JOB_RESPONSE_CODE:
                LOG.debug("FAIL, status code not 202, code is: %(code), "
                          "Error details: %(err)",
                          {'code': job_response.status_code,
                           'err': job_response.__dict__})
                return pxe_dev_nics

            job_id = job_response.__dict__['headers']['Location']
            try:
                job_id = re.search("JID_.+", job_id).group()
            except AttributeError:
                LOG.debug("FAIL: detailed error message: %(err)",
                          {'err': job_response.__dict__['_content']})
                return pxe_dev_nics
            start_time = datetime.now()
            while True:
                current_time = (datetime.now() - start_time)
                xml_data = requests.get('%s%s%s' % (
                    redfish_ip, _XML_DATA_URL, job_id), auth=(
                    redfish_username, redfish_password), verify=False)
                if _SYSTEM_CONFIG_TAG in str(xml_data.__dict__):
                    export_list = xml_data.__dict__.get('_content').split('\n')
                    export_list = [line for line in export_list
                                   if 'FQDD' in line or 'PXE' in line]
                    for i, line in enumerate(export_list):
                        if 'PXE' in line:
                            nic_id = export_list[i - 1].split('"')[1]
                            mac_response = requests.get('%s%s%s' % (
                                redfish_ip, _MAC_URL, nic_id), auth=(
                                redfish_username, redfish_password),
                                verify=False)
                            mac_address = json.loads(mac_response.__dict__.get(
                                '_content')).get('MACAddress')
                            pxe_dev_nics.append(mac_address)
                    return pxe_dev_nics
                elif current_time.seconds >= _TIMEOUT_SECONDS:
                    LOG.debug("FAIL, Timeout of %(second) seconds has been"
                              " reached before marking the job completed.",
                              {'second': _TIMEOUT_SECONDS})
                    break
        return pxe_dev_nics


class DracWSManInspect(base.InspectInterface):

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return drac_common.COMMON_PROPERTIES

    @METRICS.timer('DracInspect.validate')
    def validate(self, task):
        """Validate the driver-specific info supplied.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        manage the node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if required driver_info attribute
                 is missing or invalid on the node.

        """
        return drac_common.parse_driver_info(task.node)

    @METRICS.timer('DracInspect.inspect_hardware')
    def inspect_hardware(self, task):
        """Inspect hardware.

        Inspect hardware to obtain the essential & additional hardware
        properties.

        :param task: a TaskManager instance containing the node to act on.
        :raises: HardwareInspectionFailure, if unable to get essential
                 hardware properties.
        :returns: states.MANAGEABLE
        """

        node = task.node
        client = drac_common.get_drac_client(node)
        properties = {}

        try:
            properties['memory_mb'] = sum(
                [memory.size_mb for memory in client.list_memory()])
            cpus = client.list_cpus()
            if cpus:
                properties['cpus'] = sum(
                    [self._calculate_cpus(cpu) for cpu in cpus])
                properties['cpu_arch'] = 'x86_64' if cpus[0].arch64 else 'x86'

            bios_settings = client.list_bios_settings()
            current_capabilities = node.properties.get('capabilities', '')
            new_capabilities = {
                'boot_mode': bios_settings["BootMode"].current_value.lower()}
            capabilties = utils.get_updated_capabilities(current_capabilities,
                                                         new_capabilities)
            properties['capabilities'] = capabilties

            virtual_disks = client.list_virtual_disks()
            root_disk = self._guess_root_disk(virtual_disks)
            if root_disk:
                properties['local_gb'] = int(root_disk.size_mb / units.Ki)
            else:
                physical_disks = client.list_physical_disks()
                root_disk = self._guess_root_disk(physical_disks)
                if root_disk:
                    properties['local_gb'] = int(
                        root_disk.size_mb / units.Ki)
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to introspect node '
                      '%(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        valid_keys = self.ESSENTIAL_PROPERTIES
        missing_keys = valid_keys - set(properties)
        if missing_keys:
            error = (_('Failed to discover the following properties: '
                       '%(missing_keys)s') %
                     {'missing_keys': ', '.join(missing_keys)})
            raise exception.HardwareInspectionFailure(error=error)

        node.properties = dict(node.properties, **properties)
        node.save()

        try:
            nics = client.list_nics()
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to introspect node '
                      '%(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        pxe_dev_nics = self._get_pxe_dev_nics(client, nics, node)
        if pxe_dev_nics is None:
            LOG.warning('No PXE enabled NIC was found for node '
                        '%(node_uuid)s.', {'node_uuid': node.uuid})

        for nic in nics:
            try:
                port = objects.Port(task.context, address=nic.mac,
                                    node_id=node.id,
                                    pxe_enabled=(nic.id in pxe_dev_nics))
                port.create()

                LOG.info('Port created with MAC address %(mac)s '
                         'for node %(node_uuid)s during inspection',
                         {'mac': nic.mac, 'node_uuid': node.uuid})
            except exception.MACAlreadyExists:
                LOG.warning('Failed to create a port with MAC address '
                            '%(mac)s when inspecting the node '
                            '%(node_uuid)s because the address is already '
                            'registered',
                            {'mac': nic.mac, 'node_uuid': node.uuid})

        LOG.info('Node %s successfully inspected.', node.uuid)
        return states.MANAGEABLE

    def _guess_root_disk(self, disks, min_size_required_mb=4 * units.Ki):
        """Find a root disk.

        :param disks: list of disks.
        :param min_size_required_mb: minimum required size of the root disk in
                                     megabytes.
        :returns: root disk.
        """
        disks.sort(key=lambda disk: disk.size_mb)
        for disk in disks:
            if disk.size_mb >= min_size_required_mb:
                return disk

    def _calculate_cpus(self, cpu):
        """Find actual CPU count.

        :param cpu: Pass cpu.

        :returns: returns total cpu count.
        """
        if cpu.ht_enabled:
            return cpu.cores * 2
        else:
            return cpu.cores

    def _get_pxe_dev_nics(self, client, nics, node):
        """Get a list of pxe device interfaces.

        :param client: Dracclient to list the bios settings and nics
        :param nics: list of nics

        :returns: Returns list of pxe device interfaces.
        """
        pxe_dev_nics = []
        pxe_params = ["PxeDev1EnDis", "PxeDev2EnDis",
                      "PxeDev3EnDis", "PxeDev4EnDis"]
        pxe_nics = ["PxeDev1Interface", "PxeDev2Interface",
                    "PxeDev3Interface", "PxeDev4Interface"]

        try:
            bios_settings = client.list_bios_settings()
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to list bios settings '
                      'for %(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        if bios_settings["BootMode"].current_value == "Uefi":
            for param, nic in zip(pxe_params, pxe_nics):
                if param in bios_settings and bios_settings[
                        param].current_value == "Enabled":
                    pxe_dev_nics.append(
                        bios_settings[nic].current_value)
        elif bios_settings["BootMode"].current_value == "Bios":
            for nic in nics:
                try:
                    nic_cap = client.list_nic_settings(nic_id=nic.id)
                except drac_exceptions.BaseClientException as exc:
                    LOG.error('DRAC driver failed to list nic settings '
                              'for %(node_uuid)s. Reason: %(error)s.',
                              {'node_uuid': node.uuid, 'error': exc})
                    raise exception.HardwareInspectionFailure(error=exc)

                if ("LegacyBootProto" in nic_cap and nic_cap[
                        'LegacyBootProto'].current_value == "PXE"):
                    pxe_dev_nics.append(nic.id)

        return pxe_dev_nics


class DracInspect(DracWSManInspect):
    """Class alias of class DracWSManInspect.

    This class provides ongoing support of the deprecated 'idrac'
    inspect interface implementation entrypoint.

    All bug fixes and new features should be implemented in its base
    class, DracWSManInspect. That makes them available to both the
    deprecated 'idrac' and new 'idrac-wsman' entrypoints. Such changes
    should not be made to this class.
    """

    def __init__(self):
        LOG.warning("Inspect interface 'idrac' is deprecated and may be "
                    "removed in a future release. Use 'idrac-wsman' instead.")
