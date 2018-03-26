
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
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;


/**
 * <p>Java class for KmsResponseType complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="KmsResponseType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="KmsUri" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="UserUri" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="Time" type="{http://www.w3.org/2001/XMLSchema}dateTime"/&gt;
 *         &lt;element name="KmsId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;any processContents='lax' namespace='##other' maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="ClientReqUrl" type="{http://www.w3.org/2001/XMLSchema}anyURI"/&gt;
 *         &lt;element name="KmsMessage" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;choice minOccurs="0"&gt;
 *                   &lt;element name="KmsInit" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsInitType"/&gt;
 *                   &lt;element name="KmsKeyProv" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsKeyProvType"/&gt;
 *                   &lt;element name="KmsCertCache" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsCertCacheType"/&gt;
 *                   &lt;any processContents='lax' namespace='##other' maxOccurs="unbounded" minOccurs="0"/&gt;
 *                 &lt;/choice&gt;
 *                 &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="KmsError" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}ErrorType" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *       &lt;attribute name="Version" type="{http://www.w3.org/2001/XMLSchema}string" fixed="1.0.0" /&gt;
 *       &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KmsResponseType", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface", propOrder = {
    "kmsUri",
    "userUri",
    "time",
    "kmsId",
    "any",
    "clientReqUrl",
    "kmsMessage",
    "kmsError"
})
public class KmsResponseType {

    @XmlElement(name = "KmsUri", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String kmsUri;
    @XmlElement(name = "UserUri", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String userUri;
    @XmlElement(name = "Time", required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar time;
    @XmlElement(name = "KmsId")
    protected String kmsId;
    @XmlAnyElement(lax = true)
    protected List<Object> any;
    @XmlElement(name = "ClientReqUrl", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String clientReqUrl;
    @XmlElement(name = "KmsMessage")
    protected KmsMessage kmsMessage;
    @XmlElement(name = "KmsError")
    protected ErrorType kmsError;
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
     * Gets the value of the time property.
     *
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public XMLGregorianCalendar getTime() {
        return time;
    }

    /**
     * Sets the value of the time property.
     *
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *
     */
    public void setTime(XMLGregorianCalendar value) {
        this.time = value;
    }

    /**
     * Gets the value of the kmsId property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getKmsId() {
        return kmsId;
    }

    /**
     * Sets the value of the kmsId property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setKmsId(String value) {
        this.kmsId = value;
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
     * Gets the value of the clientReqUrl property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getClientReqUrl() {
        return clientReqUrl;
    }

    /**
     * Sets the value of the clientReqUrl property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setClientReqUrl(String value) {
        this.clientReqUrl = value;
    }

    /**
     * Gets the value of the kmsMessage property.
     *
     * @return
     *     possible object is
     *     {@link KmsMessage }
     *
     */
    public KmsMessage getKmsMessage() {
        return kmsMessage;
    }

    /**
     * Sets the value of the kmsMessage property.
     *
     * @param value
     *     allowed object is
     *     {@link KmsMessage }
     *
     */
    public void setKmsMessage(KmsMessage value) {
        this.kmsMessage = value;
    }

    /**
     * Gets the value of the kmsError property.
     *
     * @return
     *     possible object is
     *     {@link ErrorType }
     *
     */
    public ErrorType getKmsError() {
        return kmsError;
    }

    /**
     * Sets the value of the kmsError property.
     *
     * @param value
     *     allowed object is
     *     {@link ErrorType }
     *
     */
    public void setKmsError(ErrorType value) {
        this.kmsError = value;
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
            return "1.0.0";
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


    /**
     * <p>Java class for anonymous complex type.
     *
     * <p>The following schema fragment specifies the expected content contained within this class.
     *
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;choice minOccurs="0"&gt;
     *         &lt;element name="KmsInit" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsInitType"/&gt;
     *         &lt;element name="KmsKeyProv" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsKeyProvType"/&gt;
     *         &lt;element name="KmsCertCache" type="{http://www.kapsch.net/mcptt/xml/KmsInterface}KmsCertCacheType"/&gt;
     *         &lt;any processContents='lax' namespace='##other' maxOccurs="unbounded" minOccurs="0"/&gt;
     *       &lt;/choice&gt;
     *       &lt;anyAttribute processContents='lax' namespace='##other'/&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     *
     *
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "kmsInit",
        "kmsKeyProv",
        "kmsCertCache",
        "any"
    })
    public static class KmsMessage {

        @XmlElement(name = "KmsInit", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface")
        protected KmsInitType kmsInit;
        @XmlElement(name = "KmsKeyProv", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface")
        protected KmsKeyProvType kmsKeyProv;
        @XmlElement(name = "KmsCertCache", namespace = "http://www.kapsch.net/mcptt/xml/KmsInterface")
        protected KmsCertCacheType kmsCertCache;
        @XmlAnyElement(lax = true)
        protected List<Object> any;
        @XmlAnyAttribute
        private Map<QName, String> otherAttributes = new HashMap<QName, String>();

        /**
         * Gets the value of the kmsInit property.
         *
         * @return
         *     possible object is
         *     {@link KmsInitType }
         *
         */
        public KmsInitType getKmsInit() {
            return kmsInit;
        }

        /**
         * Sets the value of the kmsInit property.
         *
         * @param value
         *     allowed object is
         *     {@link KmsInitType }
         *
         */
        public void setKmsInit(KmsInitType value) {
            this.kmsInit = value;
        }

        /**
         * Gets the value of the kmsKeyProv property.
         *
         * @return
         *     possible object is
         *     {@link KmsKeyProvType }
         *
         */
        public KmsKeyProvType getKmsKeyProv() {
            return kmsKeyProv;
        }

        /**
         * Sets the value of the kmsKeyProv property.
         *
         * @param value
         *     allowed object is
         *     {@link KmsKeyProvType }
         *
         */
        public void setKmsKeyProv(KmsKeyProvType value) {
            this.kmsKeyProv = value;
        }

        /**
         * Gets the value of the kmsCertCache property.
         *
         * @return
         *     possible object is
         *     {@link KmsCertCacheType }
         *
         */
        public KmsCertCacheType getKmsCertCache() {
            return kmsCertCache;
        }

        /**
         * Sets the value of the kmsCertCache property.
         *
         * @param value
         *     allowed object is
         *     {@link KmsCertCacheType }
         *
         */
        public void setKmsCertCache(KmsCertCacheType value) {
            this.kmsCertCache = value;
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

}
