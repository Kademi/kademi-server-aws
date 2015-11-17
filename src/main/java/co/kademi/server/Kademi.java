package co.kademi.server;

import co.kademi.server.logging.WebStreamingAppender;
import com.newrelic.api.agent.HeaderType;
import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.Trace;
import io.milton.cloud.server.apps.Application;
import io.milton.cloud.server.apps.ApplicationManager;
import io.milton.cloud.server.apps.WebsocketApp;
import io.milton.cloud.server.apps.user.UserApp;
import io.milton.cloud.server.db.utils.UserDao;
import io.milton.cloud.server.manager.CacheManager;
import io.milton.cloud.server.manager.CommentService;
import io.milton.cloud.server.manager.CurrentRootFolderService;
import io.milton.cloud.server.manager.MCRootContext;
import io.milton.cloud.server.manager.WebsocketCommentsListener;
import io.milton.cloud.server.web.KademiResourceFactory;
import io.milton.cloud.server.web.KademiSecurityManager;
import io.milton.cloud.server.web.RootFolder;
import io.milton.cloud.server.web.ThreadLocalCurrentPrincipalService;
import io.milton.cloud.server.web.UserResource;
import io.milton.config.HttpManagerBuilder;
import io.milton.context.Context;
import static io.milton.context.RequestContext.C;
import io.milton.event.EventManager;
import io.milton.ftp.MiltonFtpAdapter;
import io.milton.ftp.MiltonUser;
import io.milton.grizzly.GrizzlyMiltonRequest;
import io.milton.grizzly.GrizzlyMiltonResponse;
import io.milton.http.HttpManager;
import io.milton.http.ResourceFactory;
import io.milton.http.exceptions.BadRequestException;
import io.milton.http.exceptions.NotAuthorizedException;
import io.milton.mail.MailServer;
import io.milton.mail.MailServerBuilder;
import io.milton.mail.MailboxAddress;
import io.milton.vfs.db.Organisation;
import io.milton.vfs.db.Profile;
import io.milton.vfs.db.utils.SessionManager;
import java.io.IOException;
import java.security.Security;
import java.util.Enumeration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang.StringUtils;
import org.apache.ftpserver.ftplet.Authentication;
import org.apache.ftpserver.ftplet.AuthenticationFailedException;
import org.apache.ftpserver.ftplet.FtpException;
import org.apache.ftpserver.ftplet.FtpRequest;
import org.apache.ftpserver.ftplet.User;
import org.apache.ftpserver.ftplet.UserManager;
import org.apache.ftpserver.impl.FtpIoSession;
import org.apache.ftpserver.usermanager.AnonymousAuthentication;
import org.apache.ftpserver.usermanager.UsernamePasswordAuthentication;
import org.glassfish.grizzly.http.Cookie;
import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.grizzly.http.server.util.Enumerator;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;
import org.glassfish.grizzly.websockets.OptimizedBroadcaster;
import org.glassfish.grizzly.websockets.WebSocketAddOn;
import org.glassfish.grizzly.websockets.WebSocketEngine;
import org.hibernate.Session;
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
    private CacheManager cacheManager;
    private EventManager eventManager;
    private MailServer mailServer;
    private boolean running;
    private KademiSNIService kademiSNIService;

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

        int secureHttpPort = getPropertyOrDefaultInt(KademiSNIService.SYS_SECURE_PORT, KademiSNIService.SECURE_PORT);

        if (host == null) {
            httpServer = HttpServer.createSimpleServer(null, port);
        } else {
            httpServer = HttpServer.createSimpleServer(null, host, port);
        }

        {   // Start the Kademi SNI SSL service
            KademiSNICertificateManager sniCerManager = KademiSNICertificateManager.getInstance(ctx);
            SSLEngineConfigurator sniConfig = sniCerManager.createEngineConfigurator();
            this.kademiSNIService = new KademiSNIService(secureHttpPort, sniConfig);

            this.kademiSNIService.startOn(httpServer);
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
                        NewRelic.setRequestAndResponse(new NewRelicRequest(request), new NewRelicResponse(response));
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

        MCRootContext kademiRootContext = ctx.getBean(MCRootContext.class);
        final SessionManager sessionManager = ctx.getBean(SessionManager.class);
        cacheManager = kademiRootContext.get(CacheManager.class);
        eventManager = kademiRootContext.get(EventManager.class);

        KademiWebsocketApplication kademiWebsocketApplication = new KademiWebsocketApplication(new OptimizedBroadcaster(), kademiRootContext, sessionManager, cacheManager);
        kademiRootContext.put(kademiWebsocketApplication);
        WebSocketEngine.getEngine().register("", "/comments/*", kademiWebsocketApplication);

        WebsocketCommentsListener websocketCommentsListener = new WebsocketCommentsListener(kademiWebsocketApplication);
        CommentService commentService = kademiRootContext.get(CommentService.class);
        commentService.getListeners().add(websocketCommentsListener);

        ApplicationManager applicationManager = kademiRootContext.get(ApplicationManager.class);
        for (Application app : applicationManager.getApps()) {
            if (app instanceof WebsocketApp) {
                WebsocketApp websocketApp = (WebsocketApp) app;
                websocketApp.initWebsockets(kademiRootContext, kademiWebsocketApplication);
            }
        }

        WebStreamingAppender.init(kademiRootContext.get(CurrentRootFolderService.class), kademiRootContext.get(KademiSecurityManager.class), eventManager);
        httpServer.start();
        Runtime.getRuntime().addShutdownHook(new KademiShutdownHook());

        int ftpPort = getPropertyOrDefaultInt("ftpPort", 2121);
        final KademiResourceFactory resourceFactory = kademiRootContext.get(KademiResourceFactory.class);
        KademiSecurityManager ksm = kademiRootContext.get(KademiSecurityManager.class);
        ThreadLocalCurrentPrincipalService tlcps = ctx.getBean(ThreadLocalCurrentPrincipalService.class);
        KademiFtpUserService userManager = new KademiFtpUserService(ksm, tlcps);

        try {
            MiltonFtpAdapter ftpAdapter = new MiltonFtpAdapter(resourceFactory, userManager, (final FtpIoSession ftpSession, FtpRequest request, Runnable r) -> {
                kademiRootContext.execute((Context context) -> {
                    Session session = null;
                    try {
                        session = sessionManager.open();
                        context.put(session);
                        context.put(request);
                        context.put(ftpSession);
                        KademiMiltonFtpUser user = (KademiMiltonFtpUser) ftpSession.getUser();
                        if (user != null) {
                            userManager.setCurrentFtpUser(user);
                        }

                        r.run();
                    } finally {
                        sessionManager.closeSession(session);
                        userManager.clearCurrentFtpUser();
                    }
                });
            }, ftpPort, false);
            log.info("Starting FTP server on port {}", ftpPort);
            ftpAdapter.start();
        } catch (Exception e) {
            log.error("Failed to start the FTP adapter on port " + ftpPort, e);
        }

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

            try {
                if (Kademi.this.cacheManager != null) {
                    Kademi.this.cacheManager.shutdown();
                }
            } catch (Throwable e) {

            }
            try {
                if (Kademi.this.kademiSNIService != null) {
                    Kademi.this.kademiSNIService.shutdown();
                }
            } catch (Throwable e) {

            }
        }
    }

    public class NewRelicResponse implements com.newrelic.api.agent.Response {

        private final org.glassfish.grizzly.http.server.Response r;

        public NewRelicResponse(Response r) {
            this.r = r;
        }

        @Override
        public int getStatus() throws Exception {
            return r.getStatus();
        }

        @Override
        public String getStatusMessage() throws Exception {
            return "" + r.getStatus();
        }

        @Override
        public String getContentType() {
            return r.getContentType();
        }

        @Override
        public void setHeader(String name, String val) {
            r.setHeader(name, val);
        }

        @Override
        public HeaderType getHeaderType() {
            return HeaderType.HTTP;
        }

    }

    public class NewRelicRequest implements com.newrelic.api.agent.Request {

        private final org.glassfish.grizzly.http.server.Request r;

        public NewRelicRequest(org.glassfish.grizzly.http.server.Request r) {
            this.r = r;
        }

        @Override
        public String getRequestURI() {
            return r.getRequestURI();
        }

        @Override
        public String getRemoteUser() {
            return r.getRemoteUser();
        }

        @Override
        public Enumeration getParameterNames() {
            return new Enumerator(r.getParameterNames());
        }

        @Override
        public String[] getParameterValues(String name) {
            Map<String, String[]> map = r.getParameterMap();
            if (map != null) {
                return map.get(name);
            }
            return null;
        }

        @Override
        public Object getAttribute(String name) {
            return r.getAttribute(name);
        }

        @Override
        public String getCookieValue(String name) {
            if (r.getCookies() != null) {
                for (Cookie c : r.getCookies()) {
                    if (c.getName().equals(name)) {
                        return c.getValue();
                    }
                }
            }
            return null;
        }

        @Override
        public String getHeader(String name) {
            return r.getHeader(name);
        }

        @Override
        public HeaderType getHeaderType() {
            return HeaderType.HTTP;
        }

    }

    public class KademiFtpUserService implements UserManager {

        private final KademiSecurityManager kademiSecurityManager;
        private final ThreadLocalCurrentPrincipalService tlcps;

        public KademiFtpUserService(KademiSecurityManager kademiSecurityManager, ThreadLocalCurrentPrincipalService tlcps) {
            this.kademiSecurityManager = kademiSecurityManager;
            this.tlcps = tlcps;
        }

        @Override
        public KademiMiltonFtpUser getUserByName(String userName) {
            if (!userName.contains("@")) {
                log.warn("Username must be in the form user@admindomain");
                return null;
            }
            Session session = SessionManager.session();
            MailboxAddress ma = MailboxAddress.parse(userName);
            RootFolder rf = C(CurrentRootFolderService.class).getRootFolder(ma.domain);
            if (rf != null) {
                Organisation org = rf.getOrganisation();
                Profile p = C(UserDao.class).findByUserNameOrEmailInOrgRecursive(org, ma.user, session);
                if (p != null) {
                    return new KademiMiltonFtpUser(p, org, userName, ma.domain);
                }
            }
            return null;
        }

        @Override
        public String[] getAllUserNames() throws FtpException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public void delete(String string) throws FtpException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public void save(User user) throws FtpException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public boolean doesExist(String userName) throws FtpException {
            Profile p = Profile.find(userName, SessionManager.session());
            return p != null;
        }

        @Override
        public User authenticate(Authentication authentication) throws AuthenticationFailedException {
            if (authentication instanceof UsernamePasswordAuthentication) {
                UsernamePasswordAuthentication upa = (UsernamePasswordAuthentication) authentication;
                String userName = upa.getUsername();
                String password = upa.getPassword();
                log.debug("FTP authenticate: {}", userName);
                KademiMiltonFtpUser user = getUserByName(userName);
                if (user == null) {
                    log.warn("FTP user not found {}", userName);
                    return null;
                }
                Long profileId = (Long) user.getUser();
                Session session = SessionManager.session();
                Profile p = Profile.get(profileId, session);
                if (kademiSecurityManager.getPasswordManager().verifyPassword(p, password)) {
                    setCurrentFtpUser(user);
                    return user;
                } else {
                    log.warn("Invalid FTP credentials for {}", userName);
                    return null;
                }
            } else if (authentication instanceof AnonymousAuthentication) {
                log.debug("anonymous login not supported");
                return null;
            } else {
                log.warn("unknown authentication type: " + authentication.getClass());
                return null;
            }
        }

        @Override
        public String getAdminName() throws FtpException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public boolean isAdmin(String string) throws FtpException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        private void setCurrentFtpUser(KademiMiltonFtpUser user) {
            UserResource userRes = findUserForFtp(user);
            tlcps.setCurrentPrincipal(userRes);
        }

        private UserResource findUserForFtp(KademiMiltonFtpUser user) {
            Long profileId = (Long) user.getUser();
            Session session = SessionManager.session();
            Profile p = Profile.get(profileId, session);
            RootFolder rf = C(CurrentRootFolderService.class).getRootFolder(user.getDomain());
            UserResource userRes = null;
            try {
                userRes = (UserResource) UserApp.findEntity(p, rf);
                return userRes;
            } catch (NotAuthorizedException | BadRequestException e) {
                throw new RuntimeException(e);
            }
        }

        private void clearCurrentFtpUser() {
            tlcps.setCurrentPrincipal(null);
        }

    }

    public class KademiMiltonFtpUser extends MiltonUser {

        private long orgId;
        private String domain;

        public KademiMiltonFtpUser(Profile profile, Organisation rootOrg, String miltonUserName, String domain) {
            super(profile.getId(), miltonUserName, domain);
            this.orgId = rootOrg.getId();
        }

        public long getOrgId() {
            return orgId;
        }

        public String getDomain() {
            return domain;
        }
    }
}
