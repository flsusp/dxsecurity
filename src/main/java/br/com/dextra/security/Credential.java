package br.com.dextra.security;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.Date;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import br.com.dextra.security.exceptions.TimestampParsingException;

public class Credential implements Serializable {

    private static final long serialVersionUID = 4913986898213824694L;

    protected static final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("yyyyMMdd.HHmmssSSS");

    private String username;
    private String provider;
    private Date timestamp;
    private String timestampAsString;

    public Credential(String username, String provider) {
        super();
        this.username = username;
        this.provider = provider;
        setTimestamp();
    }

    public Credential(String username, String provider, String timestamp) {
        this.username = username;
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

    public String getUsername() {
        return username;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getProvider() {
        return provider;
    }

    @Override
    public String toString() {
        return MessageFormat.format("{0}|{1}|{2}", username, provider, timestampAsString);
    }

    public Credential renew() {
        return new Credential(this.getUsername(), this.getProvider());
    }

    public static Credential parse(String token) {
        String[] tokens = splitTokens(token);

        return new Credential(tokens[0], tokens[1], tokens[2]);
    }

    public static String[] splitTokens(String token) {
        System.out.println(token);
        String[] tokens = token.split("\\|");

        return new String[] { tokens[0], tokens[1], tokens[2] };
    }
}
