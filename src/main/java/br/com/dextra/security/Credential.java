package br.com.dextra.security;

import java.io.Serializable;
import java.util.Date;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import br.com.dextra.security.exceptions.TimestampParsingException;

import com.google.common.base.Joiner;

public class Credential implements Serializable {

    private static final long serialVersionUID = 4913986898213824694L;

    protected static final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("yyyyMMdd.HHmmssSSS");

    private String userId;
    private String provider;
    private Date timestamp;
    private String timestampAsString;

    public Credential(String userId, String provider) {
        super();
        this.userId = userId;
        this.provider = provider;
        setTimestamp();
    }

    public Credential(String userId, String provider, String timestamp) {
        this.userId = userId;
        this.provider = provider;

        setTimestamp(parseDate(timestamp), timestamp);
    }

    protected Date parseDate(String timestamp) {
        try {
            return dateFormat.parseDateTime(timestamp).toDate();
        } catch (Exception e) {
            throw new TimestampParsingException(timestamp, e);
        }
    }

    protected void setTimestamp() {
        Date date = getToday();
        setTimestamp(date, dateFormat.print(date.getTime()));
    }

    protected Date getToday() {
        return new Date();
    }

    protected void setTimestamp(Date date, String timestamp) {
        this.timestamp = date;
        this.timestampAsString = timestamp;
    }

    public String getUserId() {
        return userId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getProvider() {
        return provider;
    }

    @Override
    public String toString() {
        return Joiner.on('|').join(userId, provider, timestampAsString);
    }

    public Credential renew() {
        return new Credential(this.getUserId(), this.getProvider());
    }

    public static Credential parse(String token) {
        String[] tokens = splitTokens(token);
        return new Credential(tokens[0], tokens[1], tokens[2]);
    }

    public static String[] splitTokens(String token) {
        String[] tokens = token.split("\\|");
        return new String[] { tokens[0], tokens[1], tokens[2] };
    }
}
