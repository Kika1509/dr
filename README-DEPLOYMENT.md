# KMS Deployment

## Testing environment

* java-1.8.0-openjdk-1.8.0.131
* wildfly-10.1.0.Final (Jave EE7 Full and Web Distribution)
* MariaDB-10.1.23

## MariaDb DB Schema Installation
Create DB using the defaults:
```mysql
CREATE DATABASE dr DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
CREATE USER 'dr'@'%' IDENTIFIED BY 'dr';
GRANT ALL PRIVILEGES ON *.* TO 'dr'@'%' IDENTIFIED BY 'dr' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

## Deployment of artifacts on Wildfly 10 with JSLEE SIP extension

### Build

Build with for development profile in the root of *kms* project:

    ./gradlew build
    
Build with for production profile in the root of *kms* project:

    ./gradlew -Pprod build

### Preconfiguration

See section: MariaDb DB installation

### Configuration Properties

System properties that are available for configuration (current default properties):

	spring.datasource.url=jdbc:mysql://localhost:3306/dr
	spring.datasource.username=fer
	spring.datasource.password=fer


### Artifacts for deployment

Copy following files are deployed on Wildfly server (in the *${WILDFLY_HOME}/${WILDFLY_CONFIGURATION}/deployments*):
* *kms/kms-package-war-wildfly/build/libs/kms.war*

**NOTE:** During first deployment of *kms.war* in defined schema are created all tables needed by KMS.


### Logs for *kms.war*

In case of successful deployment of kms.war following should be available in the logs:

* List of deployed beans


    TODO


* KMS version, current active profile:


    2017-09-13 11:13:09.148 DEBUG 13388 --- [kground-preinit] org.jboss.logging                        : Logging Provider: org.jboss.logging.Slf4jLoggerProvider found via system property
      _  __  __  __   ___
     | |/ / |  \/  | / __|
     | ' <  | |\/| | \__ \
     |_|\_\ |_|  |_| |___/

    :: Version:             KMS-0.2.0-RELEASE ::
    :: Running Spring Boot: 1.5.4.RELEASE ::
    :: Profile:             prod ::
    :: Cluster node:        defaultNode1 ::


* Database URL and Schema version:


    2017-09-13 11:13:16.800  INFO 13388 --- [           main] o.f.c.i.dbsupport.DbSupportFactory       : Database: jdbc:mariadb://localhost:3306/kms?useSSL=false
    2017-09-13 11:13:16.947  INFO 13388 --- [           main] o.f.core.internal.command.DbMigrate      : Current version of schema `kms`: 0.0.9.2

* Successful deployment


    16:01:04,273 INFO  [javax.enterprise.resource.webcontainer.jsf.config] (ServerService Thread Pool -- 71) Initializing Mojarra 2.2.13.SP1 20160303-1204 for context '/kms'
    16:01:08,597 INFO  [org.wildfly.extension.undertow] (ServerService Thread Pool -- 71) WFLYUT0021: Registered web context: /kms
    16:01:08,676 INFO  [org.jboss.as.server] (DeploymentScanner-threads - 2) WFLYSRV0010: Deployed "kms.war" (runtime-name : "kms.war")

* Initial first run of KMS on empty DB


	2018-01-16 12:24:48.955  INFO 6804 --- [           main] n.k.k.c.s.p.McpttKmsSecretTemplateImpl   : Container kms.example.org not found, creating initial provisioning data (certificate) for KMS URI: kms.example.org
	2018-01-16 12:25:01.052  INFO 6804 --- [           main] n.k.k.c.s.p.McpttKmsSecretTemplateImpl   : Container kms.example.org created, using initial provisioning data (certificate) from container: 0ec2ec74-a098-5e08-a967-8c3024c9d59a

* Every other run of KMS with generated initial KMS certificate


	2018-01-16 12:26:34.864  INFO 9992 --- [           main] n.k.k.c.s.p.McpttKmsSecretTemplateImpl   : Container kms.example.org found, using initial provisioning data (certificate) from container: 0ec2ec74-a098-5e08-a967-8c3024c9d59a
	2018-01-16 12:26:34.961  INFO 9992 --- [           main] n.k.k.c.s.p.McpttKmsSecretTemplateImpl   : Using z_T:61513225728804006186639550548507617816723133318735204900670403531983439382166240170885470301707574435981635586950388835084101824189507406800345667223413103680215576544048492618107253274020801478915736962717411176091564708246009990843701502494072091540576670618162425282977646742092699102986167355238229181549, KSAK:13833712000057726030178529461580602445617738620000468078708784222549772347422
	2018-01-16 12:26:35.367  INFO 9992 --- [           main] n.k.k.c.s.p.McpttKmsSecretTemplateImpl   : Using kPAK:043a9fe73195cb35b99a60ff25541bbb30fec8eb62d0d0dbec415852e7fc5e71cd93255ff11435c39efb4519e0fb116a19cd4361ececa031493a80b6feb1a625c3


