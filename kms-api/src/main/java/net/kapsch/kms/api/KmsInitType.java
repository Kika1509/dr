
package net.kapsch.kms.api;

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
import javax.xml.bind.annotation.XmlType;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;


/**
 * <p>Java class for KmsInitType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KmsInitType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;choice&gt;
 *           &lt;element name="SignedKmsCertificate" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}SignedKmsCertificateType"/&gt;
 *           &lt;element name="KmsCertificate" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsCertificateType"/&gt;
 *         &lt;/choice&gt;
 *         &lt;any processContents='lax' namespace='##other' maxOccurs="unbounded" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="Version" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KmsInitType", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface", propOrder = {
    "signedKmsCertificate",
    "kmsCertificate",
    "any"
})
public class KmsInitType {

    @XmlElement(name = "SignedKmsCertificate")
    protected SignedKmsCertificateType signedKmsCertificate;
    @XmlElement(name = "KmsCertificate")
    protected KmsCertificateType kmsCertificate;
    @XmlAnyElement(lax = true)
    protected List<Object> any;
    @XmlAttribute(name = "Id")
    protected String id;
    @XmlAttribute(name = "Version")
    protected String version;
    @XmlAnyAttribute
    private Map<QName, String> otherAttributes = new HashMap<QName, String>();

    /**
     * Gets the value of the signedKmsCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link SignedKmsCertificateType }
     *     
     */
    public SignedKmsCertificateType getSignedKmsCertificate() {
        return signedKmsCertificate;
    }

    /**
     * Sets the value of the signedKmsCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignedKmsCertificateType }
     *     
     */
    public void setSignedKmsCertificate(SignedKmsCertificateType value) {
        this.signedKmsCertificate = value;
    }

    /**
     * Gets the value of the kmsCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link KmsCertificateType }
     *     
     */
    public KmsCertificateType getKmsCertificate() {
        return kmsCertificate;
    }

    /**
     * Sets the value of the kmsCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link KmsCertificateType }
     *     
     */
    public void setKmsCertificate(KmsCertificateType value) {
        this.kmsCertificate = value;
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
        return version;
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
