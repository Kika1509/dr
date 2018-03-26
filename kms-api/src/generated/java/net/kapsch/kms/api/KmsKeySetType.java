
package net.kapsch.kms.api;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyAttribute;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;


/**
 * <p>Java class for KmsKeySetType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KmsKeySetType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="KmsUri" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="CertUri" type="{http://www.w3.org/2001/XMLSchema}anyURI" minOccurs="0"/&gt;
 *         &lt;element name="Issuer" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="UserUri" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="UserID" type="{http://www.w3.org/2001/XMLSchema}string"/&gt;
 *         &lt;element name="ValidFrom" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/&gt;
 *         &lt;element name="ValidTo" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/&gt;
 *         &lt;element name="KeyPeriodNo" type="{http://www.w3.org/2001/XMLSchema}integer"/&gt;
 *         &lt;element name="Revoked" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/&gt;
 *         &lt;element name="UserDecryptKey" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KeyContentType"/&gt;
 *         &lt;element name="UserSigningKeySSK" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KeyContentType"/&gt;
 *         &lt;element name="UserPubTokenPVT" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KeyContentType"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="Version" type="{http://www.w3.org/2001/XMLSchema}string" fixed="1.1.0" /&gt;
 *       &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KmsKeySetType", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface", propOrder = {
    "kmsUri",
    "certUri",
    "issuer",
    "userUri",
    "userID",
    "validFrom",
    "validTo",
    "keyPeriodNo",
    "revoked",
    "userDecryptKey",
    "userSigningKeySSK",
    "userPubTokenPVT"
})
public class KmsKeySetType {

    @XmlElement(name = "KmsUri", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String kmsUri;
    @XmlElement(name = "CertUri")
    @XmlSchemaType(name = "anyURI")
    protected String certUri;
    @XmlElement(name = "Issuer")
    protected String issuer;
    @XmlElement(name = "UserUri", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String userUri;
    @XmlElement(name = "UserID", required = true)
    protected String userID;
    @XmlElement(name = "ValidFrom")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validFrom;
    @XmlElement(name = "ValidTo")
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar validTo;
    @XmlElement(name = "KeyPeriodNo", required = true)
    protected BigInteger keyPeriodNo;
    @XmlElement(name = "Revoked")
    protected Boolean revoked;
    @XmlElement(name = "UserDecryptKey", required = true)
    protected KeyContentType userDecryptKey;
    @XmlElement(name = "UserSigningKeySSK", required = true)
    protected KeyContentType userSigningKeySSK;
    @XmlElement(name = "UserPubTokenPVT", required = true)
    protected KeyContentType userPubTokenPVT;
    @XmlAttribute(name = "Id")
    protected String id;
    @XmlAttribute(name = "Version")
    protected String version;
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
     * Gets the value of the userUri property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUserUri() {
        return userUri;
    }

    /**
     * Sets the value of the userUri property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUserUri(String value) {
        this.userUri = value;
    }

    /**
     * Gets the value of the userID property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUserID() {
        return userID;
    }

    /**
     * Sets the value of the userID property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUserID(String value) {
        this.userID = value;
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
     * Gets the value of the keyPeriodNo property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getKeyPeriodNo() {
        return keyPeriodNo;
    }

    /**
     * Sets the value of the keyPeriodNo property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setKeyPeriodNo(BigInteger value) {
        this.keyPeriodNo = value;
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
     * Gets the value of the userDecryptKey property.
     * 
     * @return
     *     possible object is
     *     {@link KeyContentType }
     *     
     */
    public KeyContentType getUserDecryptKey() {
        return userDecryptKey;
    }

    /**
     * Sets the value of the userDecryptKey property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyContentType }
     *     
     */
    public void setUserDecryptKey(KeyContentType value) {
        this.userDecryptKey = value;
    }

    /**
     * Gets the value of the userSigningKeySSK property.
     * 
     * @return
     *     possible object is
     *     {@link KeyContentType }
     *     
     */
    public KeyContentType getUserSigningKeySSK() {
        return userSigningKeySSK;
    }

    /**
     * Sets the value of the userSigningKeySSK property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyContentType }
     *     
     */
    public void setUserSigningKeySSK(KeyContentType value) {
        this.userSigningKeySSK = value;
    }

    /**
     * Gets the value of the userPubTokenPVT property.
     * 
     * @return
     *     possible object is
     *     {@link KeyContentType }
     *     
     */
    public KeyContentType getUserPubTokenPVT() {
        return userPubTokenPVT;
    }

    /**
     * Sets the value of the userPubTokenPVT property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyContentType }
     *     
     */
    public void setUserPubTokenPVT(KeyContentType value) {
        this.userPubTokenPVT = value;
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

}
