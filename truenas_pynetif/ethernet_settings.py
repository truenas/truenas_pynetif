from logging import getLogger
import subprocess
from typing import Self, TypedDict

from truenas_pynetif.ethtool import DeviceNotFound, OperationNotSupported, get_ethtool
from truenas_pynetif.utils import run


logger = getLogger(__name__)


class MediaInfo(TypedDict):
    """Media information for network interface."""
    media_type: str
    media_subtype: str
    active_media_type: str
    active_media_subtype: str
    supported_media: list[str]


class EthernetHardwareSettings:

    def __init__(self, interface: str):
        self._name = interface
        self._caps = self.__capabilities__()
        self._media = self.__mediainfo__()
        self._fec = self.__fec_mode__()

    def __capabilities__(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {'enabled': [], 'disabled': [], 'supported': []}
        return result

        # FIXME: unused and very inefficient with overall
        # design. Must be fixed properly in future. For now,
        # disable it.
        try:
            eth = get_ethtool()
            result = eth.get_features(self._name)
        except (OperationNotSupported, DeviceNotFound):
            pass
        except Exception:
            logger.error('Failed to get capabilities for %s', self._name, exc_info=True)
        return result

    def __set_features__(self, action: str, capabilities: list[str]) -> None:
        # c.f. comment in self.__capabilities__()
        return

        features_to_change = []
        for cap in capabilities:
            if action == 'enable' and cap in self.disabled_capabilities:
                features_to_change.append(cap)
            elif action == 'disable' and cap in self.enabled_capabilities:
                features_to_change.append(cap)

        if not features_to_change:
            return

        cmd = ['ethtool', '-K', self._name]
        value = 'on' if action == 'enable' else 'off'
        for feature in features_to_change:
            if feature not in self.supported_capabilities:
                logger.error('Feature "%s" not found on interface "%s"', feature, self._name)
                continue
            cmd.extend([feature, value])

        if len(cmd) > 3:
            try:
                run(cmd)
            except subprocess.CalledProcessError as e:
                logger.error('Failed to set features on %s: %s', self._name, e.stderr)

    @property
    def enabled_capabilities(self) -> list[str]:
        return self._caps['enabled']

    @enabled_capabilities.setter
    def enabled_capabilities(self, capabilities: list[str]) -> None:
        # c.f. comment in self.__capabilities__()
        return
        self.__set_features__('enable', capabilities)

    @property
    def disabled_capabilities(self) -> list[str]:
        return self._caps['disabled']

    @disabled_capabilities.setter
    def disabled_capabilities(self, capabilities: list[str]) -> None:
        # c.f. comment in self.__capabilities__()
        return
        self.__set_features__('disable', capabilities)

    @property
    def supported_capabilities(self) -> list[str]:
        return self._caps['supported']

    def __mediainfo__(self) -> MediaInfo:
        result: MediaInfo = {
            'media_type': '',
            'media_subtype': '',
            'active_media_type': '',
            'active_media_subtype': '',
            'supported_media': [],
        }
        try:
            eth = get_ethtool()
            link_modes = eth.get_link_modes(self._name)
            port = eth.get_link_info(self._name)['port']
            speed = link_modes['speed']
            autoneg = link_modes['autoneg']
            supported_modes = link_modes['supported_modes']
            mst = 'Unknown'
            if speed is not None and speed > 0:
                mst = f'{speed}Mb/s'
            mst = f'{mst} {port}'

            result['media_type'] = 'Ethernet'
            result['media_subtype'] = 'autoselect' if autoneg else mst
            result['active_media_type'] = 'Ethernet'
            result['active_media_subtype'] = mst
            result['supported_media'].extend(supported_modes)
        except (OperationNotSupported, DeviceNotFound):
            pass
        except Exception:
            logger.error('Failed to get media info for %s', self._name, exc_info=True)
        return result

    @property
    def media_type(self) -> str:
        return self._media['media_type']

    @property
    def media_subtype(self) -> str:
        return self._media['media_subtype']

    @property
    def active_media_type(self) -> str:
        return self._media['active_media_type']

    @property
    def active_media_subtype(self) -> str:
        return self._media['active_media_subtype']

    @property
    def supported_media(self) -> list[str]:
        return self._media['supported_media']

    def __fec_mode__(self) -> str | None:
        """Get current FEC mode."""
        try:
            eth = get_ethtool()
            return eth.get_fec(self._name)
        except (OperationNotSupported, DeviceNotFound):
            pass
        except Exception:
            logger.error('Failed to get FEC mode for %s', self._name, exc_info=True)
        return None

    @property
    def fec_mode(self) -> str | None:
        return self._fec

    def close(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, typ: object, value: object, traceback: object) -> None:
        self.close()
