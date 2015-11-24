package co.kademi.server;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Trace;
import io.milton.config.HttpManagerBuilder;
import io.milton.event.EventManager;
import io.milton.grizzly.GrizzlyMiltonRequest;
import io.milton.grizzly.GrizzlyMiltonResponse;
import io.milton.http.HttpManager;
import io.milton.http.ResourceFactory;
import io.milton.mail.MailServer;
import io.milton.mail.MailServerBuilder;
import java.io.IOException;
import java.security.Security;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang.StringUtils;
import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.grizzly.websockets.WebSocketAddOn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.support.StaticApplicationContext;

/**
 * System properties and defaults: kademi.keystore=target/keystore-kademi<br/>
 * kademi.keystore-password=password8<br/>
 * kademi.security-protoco=TLSv1.2<br/>
 * kademi.host=null<br/>
 * kademi.port=8080<br/>
 *
 *
 * @author brad
 */
public class Kademi {

    private static final Logger log = LoggerFactory.getLogger(Kademi.class);

    public static void main(String[] args) throws IOException, InterruptedException {
        Kademi k = new Kademi();
        try {
            if (k.start()) {
                System.out.println("Start completed, now in run loop");
                // todo: allow a dev argument to be passed in so you can kill server by key press
                while (true) {
                    Thread.sleep(1000);
                }
//                System.out.println("Press any key to stop the server...");
//                System.in.read();
//                System.out.println("exiting..");
//                System.exit(0);
            }
        } catch (Throwable e) {
            log.error("Exception starting server. Shutting down..", e);
            System.exit(-1);
        }

    }

    private HttpServer httpServer;
    private StaticApplicationContext parent;
    private HttpManager httpManager;
    private EventManager eventManager;
    private MailServer mailServer;
    private boolean running;

    public Kademi() {

    }

    public boolean start() throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ConfigurableApplicationContext ctx = initSpringApplicationContext();
        if (ctx == null) {
            log.warn("Failed to initialise spring");
            return false;
        }

        Object milton = ctx.getBean("milton.http.manager");
        if (milton instanceof HttpManager) {
            this.httpManager = (HttpManager) milton;
        } else if (milton instanceof HttpManagerBuilder) {
            HttpManagerBuilder builder = (HttpManagerBuilder) milton;
            ResourceFactory rf = builder.getMainResourceFactory();
            this.httpManager = builder.buildHttpManager();
        }

        if (parent.containsBean("milton.mail.server")) {
            log.info("init mailserver...");
            Object oMailServer = parent.getBean("milton.mail.server");
            if (oMailServer instanceof MailServer) {
                mailServer = (MailServer) oMailServer;
            } else if (oMailServer instanceof MailServerBuilder) {
                MailServerBuilder builder = (MailServerBuilder) oMailServer;
                mailServer = builder.build();
            } else {
                throw new RuntimeException("Unsupported type: " + oMailServer.getClass() + " expected " + MailServer.class + " or " + MailServerBuilder.class);
            }
            log.info("starting mailserver");
            mailServer.start();
        }
        log.info("Finished init");

        String host = getPropertyOrDefault("host", null);

        int port = getPropertyOrDefaultInt("port", 8080);

        if (host == null) {
            httpServer = HttpServer.createSimpleServer(null, port);
        } else {
            httpServer = HttpServer.createSimpleServer(null, host, port);
        }

        httpServer.getServerConfiguration().addHttpHandler(
                new HttpHandler() {
                    @Trace(dispatcher = true)
                    @Override
                    public void service(Request request, Response response) throws Exception {
                        log.trace("service");
                        GrizzlyMiltonRequest req = new GrizzlyMiltonRequest(request);
                        GrizzlyMiltonResponse resp = new GrizzlyMiltonResponse(response);
                        //log.info("Request Headers = {}", req.getHeaders());
                        //log.info("Request fromAddress={} remoteAddr={}", req.getFromAddress(), req.getRemoteAddr());
                        String p = req.getAbsolutePath();
                        NewRelic.setTransactionName(null, p);
                        long tm = System.currentTimeMillis();
                        httpManager.process(req, resp);
                        tm = System.currentTimeMillis() - tm;
                        NewRelic.recordResponseTimeMetric(p, tm);
                        // todo
                    }
                },
                "/");

        final WebSocketAddOn addon = new WebSocketAddOn();
        for (NetworkListener listener : httpServer.getListeners()) {
            listener.registerAddOn(addon);
        }

        System.out.println("Starting Kademi...");
        httpServer.start();
        Runtime.getRuntime().addShutdownHook(new KademiShutdownHook());

        running = true;
        return true;
    }

    @SuppressWarnings("resource")
    protected ConfigurableApplicationContext initSpringApplicationContext() {

        log.info("No root spring context");
        parent = new StaticApplicationContext();

        ConfigurableApplicationContext ctx = null;
        String[] contextFiles = new String[]{"applicationContext.xml"};
        parent.refresh();
        try {
            ctx = new ClassPathXmlApplicationContext(contextFiles, parent);
        } catch (BeansException e) {
            log.error("Unable to create a child context for Milton", e);
        }
        return ctx;

    }

    private int getPropertyOrDefaultInt(String propSuffix, int defaultVal) {
        String name = "kademi." + propSuffix;
        String s = System.getProperty(name);
        if (StringUtils.isNotBlank(s)) {
            log.info("Using System property: " + name + " = " + s);
            return Integer.parseInt(s);
        }
        log.info("Using default value " + defaultVal + " for property " + name);
        return defaultVal;
    }

    public static String getPropertyOrDefault(String propSuffix, String defaultVal) {
        String name = "kademi." + propSuffix;
        String s = System.getProperty(name);
        if (StringUtils.isNotBlank(s)) {
            log.info("Using System property: " + name + " = " + s);
            return s;
        }
        log.info("Using default value " + defaultVal + " for property " + name);
        return defaultVal;
    }

    @Override
    protected void finalize() throws Throwable {
        System.out.println("Kademi server has shutdown");
        super.finalize();
    }

    public class KademiShutdownHook extends Thread {

        @Override
        public void run() {
            System.out.println("Shutting down Kademi..");

            try {
                if (Kademi.this.httpServer != null) {
                    Kademi.this.httpServer.shutdown(3, TimeUnit.SECONDS);
                }
            } catch (Throwable e) {

            }
            try {
                if (Kademi.this.httpManager != null) {
                    Kademi.this.httpManager.shutdown();
                }
            } catch (Throwable e) {

            }
        }
    }


}
