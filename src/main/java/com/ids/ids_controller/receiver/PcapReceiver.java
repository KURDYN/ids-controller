package com.ids.ids_controller.receiver;

import com.ids.ids_controller.parser.PacketDecoder;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import reactor.netty.tcp.TcpServer;

 /**
 * https://projectreactor.io/docs/netty/release/reference/tcp-server.html - TcpSerwer generalnie
 * https://projectreactor.io/docs/netty/snapshot/api/reactor/netty/ByteBufFlux.html#asByteArray() - asByteArray
 * https://projectreactor.io/docs/core/release/api/reactor/core/publisher/Flux.html - doOnNext/Terminatee
 * */

@Component
public class PcapReceiver {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PcapReceiver.class); // inicjacja logowania

    private final PacketDecoder packetDecoder;

    /* dependency injection - aby uniknąć sztywnego tworzenia obiektów (np. new PacketDecoder()) wewnątrz klasy.
    * spring działa jak "zarządca", który tworzy instancje klas (Beany) i "wstawia" je tam, gdzie są potrzebne.
    * dla kodu: dzięki temu PcapReceiver nie musi wiedzieć, jak zbudować PacketDecoder. Interesuje go tylko to, że go dostanie i będzie mógł użyć metody .decode()
    * ala testów: można łatwo podstawić fałszywy dekoder (mock), aby przetestować samo odbieranie sieciowe, bez analizy pakietów
    * tutaj wstrzykiwanie poprzez konstruktor
    */
    public PcapReceiver(PacketDecoder packetDecoder) {
        this.packetDecoder = packetDecoder;
    }

    @PostConstruct
    public void startReceiving() {
        TcpServer.create() // Creates a TcpServer instance that is ready for configuring
                .host("0.0.0.0") // nasłuch na wszystkich interfejsach
                .port(9000)      // port zgodny z sondą
                .handle((in, out) -> { // handling połączeń in - połączenie wejściowe, out - połączenie wyjściowe
                    // in/out TO SĄ ByteBufFlux!!!!
                    log.info("Sonda połączyła się z kontrolerem.");

                    return in.receive() // patrz komentarz przy .then()
                            .asByteArray() // Returns a Flux with byte[] inside of it
                            .doOnNext(data -> { // Add behavior (side-effect) triggered when the Flux emits an item
                                log.debug("Odebrano paczkę danych: {} bajtów", data.length); // pcapy z socata przychodzą w formie surowych bajtów
                                packetDecoder.decode(data); // przekazujemy paczki danych do decodera
                            })
                            .doOnTerminate(() -> log.info("Połączenie z sondą przerwane.")) // Add behavior (side-effect) triggered when the Flux terminates, either by completing successfully
                            // or failing with an error - u nas informuje że połączenie z sonda zostało przerwane
                            .then(); // .receive().then() = Receives data from the connected client ont the in connection. then zamyka zasoby tego konkretnego handlera po zamknięciu połaczenia
                })
                .bindNow(); // Starts the server in a blocking fashion and waits for it to finish initializing
        log.info("Serwer PcapReceiver uruchomiony na porcie 9000");
    }
}
