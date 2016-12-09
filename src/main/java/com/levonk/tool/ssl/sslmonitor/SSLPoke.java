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

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

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
		@Override
		public void checkClientTrusted( X509Certificate[] certs, String arg )
				throws CertificateException
		{ }

		@Override
		public void checkServerTrusted( X509Certificate[] certs, String arg )
				throws CertificateException
		{ }

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
			System.out.println( "Usage: " + SSLPoke.class.getName()
					+ " <host> <port>" );
			System.exit(1);
		}
		final String server = args[0];

		int port = 443;
		if ( 2 == args.length )
		{
			try {
				port = Integer.parseInt( args[1] );
			} catch (NumberFormatException ex) {
				SSLPoke.log.with(ex).error("Unable to parse port");
			}
		}

		SSLPoke poke = new SSLPoke();
		boolean bSucc = false;
		bSucc = poke.testConnect( server, port );
		bSucc &= poke.testSSLDate( server, port );
		SSLPoke.log.with(bSucc).info( "SSL Test final result" );
	}

	/**
	 * Test SSL connect.
	 */
	private boolean testConnect( final String server, int port )
	{
		try {
			final SSLSocketFactory sslSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			final SSLSocket sslsocket = (SSLSocket)sslSocketFactory.createSocket( server, port );

			final InputStream in = sslsocket.getInputStream();
			final OutputStream net = sslsocket.getOutputStream();

			// Write a test byte to get a response
			net.write(1);

			while ( 0 < in.available() )
			{
				SSLPoke.log.info(in.read());
			}
			return true;

		} catch (Exception ex ) {
			SSLPoke.log.with(ex).error("trying to open source and read output");
		}
		return false;
	}

	/**
	 * Test SSL date/
	 */
	private boolean testSSLDate( final String server, int port )
	{
		try {
			final SSLContext ctx = SSLContext.getInstance( "TLS" );
			ctx.init( new KeyManager[0], new TrustManager[]
					{
						new BogusTrustManager()
					},
					new SecureRandom()
					);
			SSLContext.setDefault( ctx );

			final URL url = new URL( "https://" + server + ":" + Integer.toString(port) + "/" );
			final HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
			conn.setHostnameVerifier( new HostnameVerifier() {
					@Override
					public boolean verify( String arg0, SSLSession arg1) {
						return true;
					}
			});
			SSLPoke.log.with(conn.getResponseCode()).info("Response Code");
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
					SSLPoke.log.with(server).with(port).with(x509).with(x509.getNotAfter()).warn( "Certificate will expire within " + EXPIRE_WARN_MONTHS + " months" );
					return false;
				}
			}

			conn.disconnect();
			return true;
		} catch (Exception ex ) {
			SSLPoke.log.with(ex).error("trying to check expiration date");
		}
		return false;

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

