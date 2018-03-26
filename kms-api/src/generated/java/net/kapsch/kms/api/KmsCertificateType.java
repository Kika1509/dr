
package net.kapsch.kms.api;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyAttribute;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;


/**
 * <p>Java class for KmsCertificateType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="KmsCertificateType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="KmsUri" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="CertUri" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="Issuer" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="ValidFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/&gt;
 *         &lt;element name="ValidTo" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/&gt;
 *         &lt;element name="Revoked" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/&gt;
 *         &lt;element name="UserIdFormat" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="UserKeyPeriod" type="{http://www.w3.org/2001/XMLSchema}integer"/&gt;
 *         &lt;element name="UserKeyOffset" type="{http://www.w3.org/2001/XMLSchema}integer"/&gt;
 *         &lt;element name="PubEncKey" type="{http://www.w3.org/2001/XMLSchema}hexBinary"/&gt;
 *         &lt;element name="PubAuthKey" type="{http://www.w3.org/2001/XMLSchema}hexBinary"/&gt;
 *         &lt;element name="ParameterSet" type="{http://www.w3.org/2001/XMLSchema}integer" minOccurs="0"/&gt;
 *         &lt;element name="KmsDomainList" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="KmsDomain" type="{http://www.w3.org/2001/XMLSchema}anyURI" maxOccurs="unbounded"/&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;any processContents='lax' namespace='##other' maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="Version" type="{http://www.w3.org/2001/XMLSchema}string" fixed="1.1.0" /&gt;
 *       &lt;attribute name="Role" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}RoleType" /&gt;
 *       &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KmsCertificateType", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface", propOrder = {
    "kmsUri",
    "certUri",
    "issuer",
    "validFrom",
    "validTo",
    "revoked",
    "userIdFormat",
    "userKeyPeriod",
    "userKeyOffset",
    "pubEncKey",
    "pubAuthKey",
    "parameterSet",
    "kmsDomainList",
    "any"
})
public class KmsCertificateType {

    @XmlElement(name = "KmsUri", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String kmsUri;
    @XmlElement(name = "CertUri")
    @XmlSchemaType(name = "anyURI")
    protected String certUri;
    @XmlElement(name = "Issuer")
    protected String issuer;
    @XmlElement(name = "ValidFrom")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFrom;
    @XmlElement(name = "ValidTo")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validTo;
    @XmlElement(name = "Revoked")
    protected Boolean revoked;
    @XmlElement(name = "UserIdFormat", required = true)
    protected String userIdFormat;
    @XmlElement(name = "UserKeyPeriod", required = true)
    protected BigInteger userKeyPeriod;
    @XmlElement(name = "UserKeyOffset", required = true)
    protected BigInteger userKeyOffset;
    @XmlElement(name = "PubEncKey", required = true, type = String.class)
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] pubEncKey;
    @XmlElement(name = "PubAuthKey", required = true, type = String.class)
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] pubAuthKey;
    @XmlElement(name = "ParameterSet")
    protected BigInteger parameterSet;
    @XmlElement(name = "KmsDomainList")
    protected KmsDomainList kmsDomainList;
    @XmlAnyElement(lax = true)
    protected List<Object> any;
    @XmlAttribute(name = "Id")
    protected String id;
    @XmlAttribute(name = "Version")
    protected String version;
    @XmlAttribute(name = "Role")
    protected RoleType role;
    @XmlAnyAttribute
    private Map<QName, String> otherAttributes = new HashMap<QName, String>();

    /**
     * Gets the value of the kmsUri property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getKmsUri() {
        return kmsUri;
    }

    /**
     * Sets the value of the kmsUri property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setKmsUri(String value) {
        this.kmsUri = value;
    }

    /**
     * Gets the value of the certUri property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getCertUri() {
        return certUri;
    }

    /**
     * Sets the value of the certUri property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setCertUri(String value) {
        this.certUri = value;
    }

    /**
     * Gets the value of the issuer property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the value of the issuer property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setIssuer(String value) {
        this.issuer = value;
    }

    /**
     * Gets the value of the validFrom property.
     *
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public XMLGregorianCalendar getValidFrom() {
        return validFrom;
    }

    /**
     * Sets the value of the validFrom property.
     *
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public void setValidFrom(XMLGregorianCalendar value) {
        this.validFrom = value;
    }

    /**
     * Gets the value of the validTo property.
     *
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public XMLGregorianCalendar getValidTo() {
        return validTo;
    }

    /**
     * Sets the value of the validTo property.
     *
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public void setValidTo(XMLGregorianCalendar value) {
        this.validTo = value;
    }

    /**
     * Gets the value of the revoked property.
     *
     * @return
     *     possible object is
     *     {@link Boolean }
     *
     */
    public Boolean isRevoked() {
        return revoked;
    }

    /**
     * Sets the value of the revoked property.
     *
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *
     */
    public void setRevoked(Boolean value) {
        this.revoked = value;
    }

    /**
     * Gets the value of the userIdFormat property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getUserIdFormat() {
        return userIdFormat;
    }

    /**
     * Sets the value of the userIdFormat property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setUserIdFormat(String value) {
        this.userIdFormat = value;
    }

    /**
     * Gets the value of the userKeyPeriod property.
     *
     * @return
     *     possible object is
     *     {@link BigInteger }
     *
     */
    public BigInteger getUserKeyPeriod() {
        return userKeyPeriod;
    }

    /**
     * Sets the value of the userKeyPeriod property.
     *
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *
     */
    public void setUserKeyPeriod(BigInteger value) {
        this.userKeyPeriod = value;
    }

    /**
     * Gets the value of the userKeyOffset property.
     *
     * @return
     *     possible object is
     *     {@link BigInteger }
     *
     */
    public BigInteger getUserKeyOffset() {
        return userKeyOffset;
    }

    /**
     * Sets the value of the userKeyOffset property.
     *
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *
     */
    public void setUserKeyOffset(BigInteger value) {
        this.userKeyOffset = value;
    }

    /**
     * Gets the value of the pubEncKey property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public byte[] getPubEncKey() {
        return pubEncKey;
    }

    /**
     * Sets the value of the pubEncKey property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setPubEncKey(byte[] value) {
        this.pubEncKey = value;
    }

    /**
     * Gets the value of the pubAuthKey property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public byte[] getPubAuthKey() {
        return pubAuthKey;
    }

    /**
     * Sets the value of the pubAuthKey property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setPubAuthKey(byte[] value) {
        this.pubAuthKey = value;
    }

    /**
     * Gets the value of the parameterSet property.
     *
     * @return
     *     possible object is
     *     {@link BigInteger }
     *
     */
    public BigInteger getParameterSet() {
        return parameterSet;
    }

    /**
     * Sets the value of the parameterSet property.
     *
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *
     */
    public void setParameterSet(BigInteger value) {
        this.parameterSet = value;
    }

    /**
     * Gets the value of the kmsDomainList property.
     *
     * @return
     *     possible object is
     *     {@link KmsDomainList }
     *
     */
    public KmsDomainList getKmsDomainList() {
        return kmsDomainList;
    }

    /**
     * Sets the value of the kmsDomainList property.
     *
     * @param value
     *     allowed object is
     *     {@link KmsDomainList }
     *
     */
    public void setKmsDomainList(KmsDomainList value) {
        this.kmsDomainList = value;
    }

    /**
     * Gets the value of the any property.
     *
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the any property.
     *
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAny().add(newItem);
     * </pre>
     *
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Element }
     * {@link Object }
     *
     *
     */
    public List<Object> getAny() {
        if (any == null) {
            any = new ArrayList<Object>();
        }
        return this.any;
    }

    /**
     * Gets the value of the id property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the version property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getVersion() {
        if (version == null) {
            return "1.1.0";
        } else {
            return version;
        }
    }

    /**
     * Sets the value of the version property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setVersion(String value) {
        this.version = value;
    }

    /**
     * Gets the value of the role property.
     *
     * @return
     *     possible object is
     *     {@link RoleType }
     *
     */
    public RoleType getRole() {
        return role;
    }

    /**
     * Sets the value of the role property.
     *
     * @param value
     *     allowed object is
     *     {@link RoleType }
     *
     */
    public void setRole(RoleType value) {
        this.role = value;
    }

    /**
     * Gets a map that contains attributes that aren't bound to any typed property on this class.
     *
     * <p>
     * the map is keyed by the name of the attribute and
     * the value is the string value of the attribute.
     *
     * the map returned by this method is live, and you can add new attribute
     * by updating the map directly. Because of this design, there's no setter.
     *
     *
     * @return
     *     always non-null
     */
    public Map<QName, String> getOtherAttributes() {
        return otherAttributes;
    }


    /**
     * <p>Java class for anonymous complex type.
     *
     * <p>The following schema fragment specifies the expected content contained within this class.
     *
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;sequence&gt;
     *         &lt;element name="KmsDomain" type="{http://www.w3.org/2001/XMLSchema}anyURI" maxOccurs="unbounded"/&gt;
     *       &lt;/sequence&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     *
     *
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "kmsDomain"
    })
    public static class KmsDomainList {

        @XmlElement(name = "KmsDomain", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface", required = true)
        @XmlSchemaType(name = "anyURI")
        protected List<String> kmsDomain;

        /**
         * Gets the value of the kmsDomain property.
         *
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the kmsDomain property.
         *
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getKmsDomain().add(newItem);
         * </pre>
         *
         *
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link String }
         *
         *
         */
        public List<String> getKmsDomain() {
            if (kmsDomain == null) {
                kmsDomain = new ArrayList<String>();
            }
            return this.kmsDomain;
        }

    }

}
