# KMS Development Environment

## Gradle

Use gradle wrapper for building the project.

## IntelliJ IDEA

* Plugins
    * Eclipse Code Formatter
        * Setup in IntelliJ Settings: 
            * check Use the Eclipse code formatter
            * put path to config/kapsch-code-conventions.xml in Eclipse Java Formatter config file
            * put path to config/kapsch.importorder in Import order/From file   
* Settings
    * Editor -> Code Style -> Java -> Imports
    
            Class count to use import with '*': 100
            Names count to user static import with '*': 100      

## Eclipse

* Plugins
    * Checkstyle Plug-in
        * Setup in Eclipse preferences: 
            * add new Global Check Configuration (Project relative configuration pointing to /kms/config/checkstyle/checkstyle.xml)
            * in "Additional properties" define the property named "configDir" pointing to file system location of /kms/config/checkstyle directory
               
* Settings
    * Java -> Code Style -> Formatter
    		Import new profile from: config/kapsch-code-conventions.xml
    * Java -> Code Style -> Organize Imports
    		Import new profile from: config/kapsch.importorder
    * Java -> Editor -> Save Actions
    		check all of the following:
    		- Perform the selected actions on save
    		- Format source code -> Format all lines
    		- Organize imports
    		- Additional actions -> Remove trailing white spaces on all lines