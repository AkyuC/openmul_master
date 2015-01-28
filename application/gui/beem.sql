CREATE DATABASE  IF NOT EXISTS `beem` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `beem`;
-- MySQL dump 10.13  Distrib 5.6.17, for Win64 (x86_64)
--
-- Host: localhost    Database: beem
-- ------------------------------------------------------
-- Server version	5.6.22

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `apiserver`
--

DROP TABLE IF EXISTS `apiserver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `apiserver` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(45) DEFAULT NULL,
  `api_protocol` varchar(10) DEFAULT NULL,
  `api_address` varchar(45) DEFAULT NULL,
  `api_port` varchar(10) DEFAULT NULL,
  `api_version` varchar(10) DEFAULT NULL,
  `used` varchar(1) DEFAULT 'Y',
  PRIMARY KEY (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `apiserver`
--

LOCK TABLES `apiserver` WRITE;
/*!40000 ALTER TABLE `apiserver` DISABLE KEYS */;
INSERT INTO `apiserver` VALUES (1,'Standard 1','https','203.255.254.108','9191','1.0','Y');
/*!40000 ALTER TABLE `apiserver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `flow`
--

DROP TABLE IF EXISTS `flow`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `flow` (
  `seq` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `priority` varchar(10) DEFAULT NULL,
  `byte_count` varchar(10) DEFAULT NULL,
  `packet_count` varchar(10) DEFAULT NULL,
  `alive` varchar(10) DEFAULT NULL,
  `pps` varchar(10) DEFAULT NULL,
  `bps` varchar(10) DEFAULT NULL,
  `flags` varchar(100) DEFAULT NULL,
  `flow_id` varchar(200) DEFAULT NULL,
  `table_id` varchar(10) DEFAULT NULL,
  `in_port` varchar(10) DEFAULT NULL,
  `dl_dst` varchar(20) DEFAULT NULL,
  `dl_src` varchar(20) DEFAULT NULL,
  `dl_type` varchar(16) DEFAULT NULL,
  `dl_vlan` varchar(10) DEFAULT NULL,
  `dl_vlan_pcp` varchar(10) DEFAULT NULL,
  `mpls_bos` varchar(10) DEFAULT NULL,
  `mpls_tc` varchar(10) DEFAULT NULL,
  `mpls_label` varchar(10) DEFAULT NULL,
  `nw_src` varchar(50) DEFAULT NULL,
  `nw_dst` varchar(50) DEFAULT NULL,
  `nw_tos` varchar(20) DEFAULT NULL,
  `nw_proto` varchar(10) DEFAULT NULL,
  `tp_src` varchar(10) DEFAULT NULL,
  `tp_dst` varchar(10) DEFAULT NULL,
  `out_port` varchar(10) DEFAULT NULL,
  `actions` varchar(256) DEFAULT NULL,
  `description` varchar(140) DEFAULT NULL,
  `star` varchar(1) DEFAULT NULL,
  `dpid` varchar(16) DEFAULT NULL,
  `nbapi` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=12355714 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `flow`
--

LOCK TABLES `flow` WRITE;
/*!40000 ALTER TABLE `flow` DISABLE KEYS */;
/*!40000 ALTER TABLE `flow` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `flowaux`
--

DROP TABLE IF EXISTS `flowaux`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `flowaux` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `flow_id` varchar(200) DEFAULT NULL,
  `description` varchar(140) DEFAULT NULL,
  `star` varchar(1) DEFAULT NULL,
  `nbapi` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `flowaux`
--

LOCK TABLES `flowaux` WRITE;
/*!40000 ALTER TABLE `flowaux` DISABLE KEYS */;
/*!40000 ALTER TABLE `flowaux` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `notification`
--

DROP TABLE IF EXISTS `notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notification` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(10) DEFAULT NULL,
  `body` varchar(256) DEFAULT NULL,
  `regdt` datetime DEFAULT NULL,
  `hit` int(11) DEFAULT '0',
  `hitdt` datetime DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `notification`
--

LOCK TABLES `notification` WRITE;
/*!40000 ALTER TABLE `notification` DISABLE KEYS */;
/*!40000 ALTER TABLE `notification` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `port`
--

DROP TABLE IF EXISTS `port`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `port` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `hw_addr` varchar(24) DEFAULT NULL,
  `state` varchar(16) DEFAULT NULL,
  `curr` varchar(16) DEFAULT NULL,
  `name` varchar(24) DEFAULT NULL,
  `advertised` varchar(24) DEFAULT NULL,
  `peer` varchar(24) DEFAULT NULL,
  `supported` varchar(24) DEFAULT NULL,
  `config` varchar(16) DEFAULT NULL,
  `port_no` varchar(16) DEFAULT NULL,
  `star` varchar(1) DEFAULT NULL,
  `dpid` varchar(16) DEFAULT NULL,
  `nbapi` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=343099 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `port`
--

LOCK TABLES `port` WRITE;
/*!40000 ALTER TABLE `port` DISABLE KEYS */;
/*!40000 ALTER TABLE `port` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `portaux`
--

DROP TABLE IF EXISTS `portaux`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `portaux` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `port_no` varchar(16) DEFAULT NULL,
  `star` varchar(1) DEFAULT NULL,
  `dpid` varchar(16) DEFAULT NULL,
  `nbapi` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `portaux`
--

LOCK TABLES `portaux` WRITE;
/*!40000 ALTER TABLE `portaux` DISABLE KEYS */;
/*!40000 ALTER TABLE `portaux` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `switchaux`
--

DROP TABLE IF EXISTS `switchaux`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `switchaux` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `dpid` varchar(16) DEFAULT NULL,
  `description` varchar(45) DEFAULT NULL,
  `nbapi` varchar(25) DEFAULT NULL,
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `switchaux`
--

LOCK TABLES `switchaux` WRITE;
/*!40000 ALTER TABLE `switchaux` DISABLE KEYS */;
/*!40000 ALTER TABLE `switchaux` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `seq` int(11) NOT NULL AUTO_INCREMENT,
  `id` varchar(45) DEFAULT NULL,
  `passwd` varchar(45) DEFAULT NULL,
  `name` varchar(45) DEFAULT NULL,
  `list_cnt` int(11) DEFAULT '10',
  `api_protocol` varchar(10) DEFAULT 'https',
  `api_address` varchar(45) DEFAULT 'localhost',
  `api_port` varchar(10) DEFAULT '9191',
  `api_version` varchar(10) DEFAULT '1.0',
  `acl` varchar(8) DEFAULT 'user',
  PRIMARY KEY (`seq`),
  UNIQUE KEY `seq_UNIQUE` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'admin','admin','Admin',10,'http','127.0.0.1','8181','1.0','admin');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-01-21 12:56:23
