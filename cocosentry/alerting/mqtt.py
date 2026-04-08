"""MQTT publish backend."""

from __future__ import annotations

import json
import logging

from cocosentry.alerting.engine import AlertBackend
from cocosentry.config import MqttConfig
from cocosentry.storage.models import Alert

logger = logging.getLogger(__name__)


class MqttBackend(AlertBackend):
    """Publishes alerts to an MQTT broker."""

    def __init__(self, config: MqttConfig):
        self.broker = config.broker
        self.port = config.port
        self.topic = config.topic
        self._client = None

        try:
            import paho.mqtt.client as mqtt
            self._client = mqtt.Client(
                client_id="cocosentry",
                protocol=mqtt.MQTTv5,
            )

            if config.tls:
                self._client.tls_set()  # uses system CA store
                if config.port == 1883:
                    logger.warning(
                        "MQTT TLS enabled but port is 1883; "
                        "standard TLS port is 8883"
                    )

            if config.username:
                self._client.username_pw_set(config.username, config.password)

            self._client.connect(self.broker, self.port, keepalive=60)
            self._client.loop_start()
            logger.info("MQTT connected to %s:%d", self.broker, self.port)
        except ImportError:
            logger.error("paho-mqtt not installed — MQTT backend disabled")
        except Exception as e:
            logger.error("MQTT connection failed: %s", e)
            self._client = None

    async def send(self, alert: Alert) -> bool:
        if self._client is None:
            return False

        payload = json.dumps(alert.to_dict(), default=str)

        try:
            result = self._client.publish(
                self.topic,
                payload=payload,
                qos=1,
            )
            if result.rc == 0:
                logger.debug("MQTT alert published: %s", alert.title)
                return True
            logger.error("MQTT publish failed: rc=%d", result.rc)
            return False
        except Exception as e:
            logger.error("MQTT publish error: %s", e)
            return False

    def close(self) -> None:
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
