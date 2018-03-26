package net.kapsch.kms.api.time;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

import org.apache.commons.net.ntp.TimeStamp;

/**
 * Utility class for NTP to Java time manipulation
 */
public class TimeUtils {
	private final static long NTP_JAVA_EPOCH_DIFF = 2208988800L;
	private final static ZoneOffset DEFAULT_TIMEZONE = ZoneOffset.ofHours(0);

	protected TimeUtils() {
	}

	public static LocalDateTime fromNtpTimestamp(TimeStamp timestamp) {
		return LocalDateTime.ofInstant(timestamp.getDate().toInstant(), DEFAULT_TIMEZONE);
	}

	public static LocalDateTime fromNtpEpochSeconds(long ntpEpochSeconds) {
		return LocalDateTime.ofEpochSecond(ntpEpochSeconds - NTP_JAVA_EPOCH_DIFF, 0,
				ZoneOffset.UTC);
	}

	public static long secondsFromNtpEpochTo(LocalDateTime dateTime) {
		return new TimeStamp(Date.from(dateTime.toInstant(ZoneOffset.UTC))).getSeconds();
	}

	public static TimeStamp fromNtpEpochTo(LocalDateTime dateTime) {
		return new TimeStamp(Date.from(dateTime.toInstant(ZoneOffset.UTC)));
	}
}
