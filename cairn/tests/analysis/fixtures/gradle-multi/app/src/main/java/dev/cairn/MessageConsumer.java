package dev.cairn;

import org.springframework.kafka.annotation.KafkaListener;

public class MessageConsumer {
    @KafkaListener(topics = "events")
    public void consume(String message) {
        new java.net.URL(message);
    }
}
