// see https://logging.apache.org/log4j/2.x/manual/usage.html
// see https://logging.apache.org/log4j/2.x/manual/lookups.html

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class Server {
    final static Logger log = LogManager.getLogger(Server.class);

    public static void main(String[] args) throws Exception {
        final int httpServerPort = 8080;
        final int tcpServerPort = 8081;

        // start a TCP server to simulate a non-responding JNDI callable LDAP server.
        final Thread tcpServerThread = new Thread() {
            @Override
            public void run() {
                try {
                    log.info("Starting TCP server (to simulate non-responding JNDI callable LDAP server) at tcp://localhost:{}", tcpServerPort);
                    final ServerSocket serverSocket = new ServerSocket(tcpServerPort);
                    while (true) {
                        final Socket clientSocket = serverSocket.accept();
                        log.warn("Got Oopsie Daisy TCP Request from {}", clientSocket.getInetAddress().getHostAddress());
                        clientSocket.close();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        tcpServerThread.start();

        // log a self inflicted jndi lookup.
        log.info("Log self-inflicted jndi log4j lookup: {}", String.format("${jndi:ldap://127.0.0.1:%d}", tcpServerPort));

        // let the user remotely log the data from the X-Api-Version header.
        final HttpServer httpServer = HttpServer.create(new InetSocketAddress(httpServerPort), 0);
        httpServer.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange httpExchange) throws IOException {
                log.info("Got HTTP request: {} {}", httpExchange.getRequestMethod(), httpExchange.getRequestURI());
                for (final String apiVersion : httpExchange.getRequestHeaders().get("X-Api-Version")) {
                    log.info("Log HTTP request header X-Api-Version: {}", apiVersion);
                }
                final byte[] responseBodyBytes = "Okidoki\n".getBytes();
                httpExchange.sendResponseHeaders(200, responseBodyBytes.length);
                final OutputStream os = httpExchange.getResponseBody();
                os.write(responseBodyBytes);
                os.close();
            }
        });
        log.info("Starting HTTP server at http://localhost:{}", httpServerPort);
        httpServer.start();
    }
}