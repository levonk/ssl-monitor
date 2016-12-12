package com.levonk.tool.ssl.sslmonitor;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Set;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jclouds.ContextBuilder;
import org.jclouds.compute.ComputeService;
import org.jclouds.compute.ComputeServiceContext;
import org.jclouds.compute.domain.ComputeMetadata;
import org.jclouds.ec2.domain.SecurityGroup;

import com.godaddy.logging.Logger;
import com.godaddy.logging.LoggerFactory;

/**
 * Test SSL Setup.
 *
 * Establish a SSL connection to a host and port, writes a byte and prints the response.
 * @see http://confluence.atlassian.com/display/JIRA/Connecting+to+SSL+services
 */
public class SSLPoke
{
	private static final Logger log = LoggerFactory.getLogger(SSLPoke.class);

	private static class BogusTrustManager implements X509TrustManager
	{
		public BogusTrustManager() {
			// TODO Auto-generated constructor stub
		}

		@Override
		public void checkClientTrusted( X509Certificate[] certs, String arg )
				throws CertificateException
		{ /* unecessary */ }

		@Override
		public void checkServerTrusted( X509Certificate[] certs, String arg )
				throws CertificateException
		{ /* unecessary */ }

		@Override
		public X509Certificate[] getAcceptedIssuers()
		{
			return null;
		}
	}


	public static void main( String[] args )
	{
		if ( (2 != args.length) && (1 != args.length) )
		{
			System.out.println( Messages.getString("SSLPoke.USAGE_PREFIX") + SSLPoke.class.getName() //$NON-NLS-1$
					+ Messages.getString("SSLPoke.USAGE_ARGS") ); //$NON-NLS-1$
			System.exit(1);
		}
		final String server = args[0];

		int port = 443;
		if ( 2 == args.length )
		{
			try {
				port = Integer.parseInt( args[1] );
			} catch (NumberFormatException ex) {
				SSLPoke.log.with(ex).error(Messages.getString("SSLPoke.USAGE_WARN_PORT")); //$NON-NLS-1$
			}
		}

		boolean bSucc = false;
		bSucc = SSLPoke.testConnect( server, port );
		bSucc &= SSLPoke.testSSLDate( server, port );
		SSLPoke.log.with(Boolean.valueOf(bSucc)).info( Messages.getString("SSLPoke.RESPONSE_HEADING") ); //$NON-NLS-1$
	}

	/**
	 * Test SSL connect.
	 */
	private static boolean testConnect( final String server, int port )
	{
		final SSLSocketFactory sslSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();	

		try (
			final SSLSocket sslsocket = (SSLSocket)sslSocketFactory.createSocket(server, port);
			final InputStream in = sslsocket.getInputStream();
			final OutputStream net = sslsocket.getOutputStream();
		) {

			// Write a test byte to get a response
			net.write(1);

			while ( 0 < in.available() )
			{
				SSLPoke.log.debug(Messages.getString("SSLPoke.RESPONSE_BYTES_READ"), Integer.valueOf(in.read())); //$NON-NLS-1$
			}
			return true;

		} catch (Exception ex ) {
			SSLPoke.log.with(ex).error(Messages.getString("SSLPoke.EXCEPT_SSLCONNECT")); //$NON-NLS-1$
		}
		return false;
	}

	/**
	 * Test SSL date/
	 */
	private static boolean testSSLDate( final String server, int port )
	{
		try {
			final SSLContext ctx = SSLContext.getInstance( "TLS" ); //$NON-NLS-1$
			ctx.init( new KeyManager[0], new TrustManager[]
					{
						new BogusTrustManager()
					},
					new SecureRandom()
					);
			SSLContext.setDefault( ctx );

			final URL url = new URL( "https://" + server + ":" + Integer.toString(port) + "/" ); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			final HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
			conn.setHostnameVerifier( new HostnameVerifier() {
					@Override
					public boolean verify( String arg0, SSLSession arg1) {
						return true;
					}
			});
			SSLPoke.log.with(Integer.valueOf(conn.getResponseCode())).info(Messages.getString("SSLPoke.RESPONSE_CODE")); //$NON-NLS-1$
			Certificate[] certs = conn.getServerCertificates();
			for ( Certificate cert : certs )
			{
				//System.out.println( cert.getType() );
				//System.out.println( cert );
				final X509Certificate x509 = (X509Certificate)cert;
				final Date today = new Date();
				x509.checkValidity(today);

				// We just (above) checked for not ready and expired,
				// Let's check three months earlier for warning
				// Three months should be enough
				final Instant instant = x509.getNotAfter().toInstant();
				final ZonedDateTime zdt = instant.atZone( ZoneId.systemDefault() );
				final int EXPIRE_WARN_MONTHS = 3;
				final LocalDate warnDate = zdt.toLocalDate().minusMonths( EXPIRE_WARN_MONTHS );
				final LocalDate todayLD = LocalDate.now();
				if ( todayLD.isAfter(warnDate)  )
				{
					SSLPoke.log.with(server).with(Integer.valueOf(port))
							.with(x509).with(x509.getNotAfter())
							.warn( Messages.getString("SSLPoke.CERT_EXPIRE_WITHIN") //$NON-NLS-1$
							+ EXPIRE_WARN_MONTHS + Messages.getString("SSLPoke.MONTHS") ); //$NON-NLS-1$
					return false;
				}
			}

			conn.disconnect();
			return true;
		} catch (Exception ex ) {
			SSLPoke.log.with(ex).error(Messages.getString("SSLPoke.EXCEPT_EXPIRE_DATE")); //$NON-NLS-1$
		}
		return false;
	}
	
	private static final ComputeService getCompute()
	{
		final String provider = "us-east-1";
		final String identity = "identity";
		final String credential = "credential";
		ContextBuilder builder = ContextBuilder.newBuilder(provider )
				.credentials(identity, credential);
		return builder.buildView(SecurityGroup.class).getComputeService();
	}
	
	private static final getLoadBalancers( final ComputeService compute )
	{
		Set<SecurityGroup> listNodes = compute.li .listNodes();
		for ( SecurityGroup sg : listNodes )
		{
			cm.
		}
	
	}
}

/*
 * Usage:
 * 1. Extract cert from server
 *		> openssl s_client -connect server:443
 * 2. Negative test cert / keytool
 *		> java SSLPoke server 443
 *	  You should get something like
 *		> javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed:
 *		>	sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
 * 3. Import cert into default keytool:
 *		> keytool -import -alias alias.server.com -keystore $JAVA_HOME/jre/lib/security/cacerts
 * 4. positive test cert / keytool:
 *		> java SSLPoke server 443
 *	  you should get this:
 *		> Successfully connected.
 */

