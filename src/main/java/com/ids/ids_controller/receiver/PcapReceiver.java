package com.ids.ids_controller.receiver;

import com.ids.ids_controller.parser.PacketDecoder;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import reactor.netty.tcp.TcpServer;

@Component
public class PcapReceiver {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PcapReceiver.class);

    private final PacketDecoder packetDecoder;

    // Ręczny konstruktor - Spring go użyje do wstrzyknięcia PacketDecoder
    public PcapReceiver(PacketDecoder packetDecoder) {
        this.packetDecoder = packetDecoder;
    }

    @PostConstruct
    public void startReceiving() {
        TcpServer.create()
                .host("0.0.0.0") // Nasłuchuj na wszystkich interfejsach
                .port(9000)      // Port zgodny z Twoją sondą
                .handle((in, out) -> {
                    log.info("Sonda połączyła się z kontrolerem.");

                    return in.receive()
                            .asByteArray()
                            .doOnNext(data -> {
                                // Tutaj wpadają surowe bajty pcap
                                log.debug("Odebrano paczkę danych: {} bajtów", data.length);
                                packetDecoder.decode(data);
                            })
                            .doOnTerminate(() -> log.info("Połączenie z sondą przerwane."))
                            .then();
                })
                .bindNow();

        log.info("Serwer PcapReceiver uruchomiony na porcie 9000");
    }
}
