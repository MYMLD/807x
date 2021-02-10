# Copyright (C) 2016 Openwrt.org
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-turboacc
PKG_VERSION:=1.0
PKG_RELEASE:=2

PKG_LICENSE:=GPLv3.0+

LUCI_TITLE:=LuCI support for Shortcut-FE
LUCI_DEPENDS:=+pdnsd-alt \
              +PACKAGE_$(PKG_NAME)_INCLUDE_shortcut-fe:kmod-fast-classifier \
              +PACKAGE_$(PKG_NAME)_INCLUDE-hybla-cca:kmod-tcp-hybla \
              +PACKAGE_$(PKG_NAME)_INCLUDE_dnsforwarder:dnsforwarder
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/config
config PACKAGE_$(PKG_NAME)_INCLUDE_shortcut-fe
	bool "Include Shortcut-FE"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_hybla-cca
	bool "Include HYBLA CCA"
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_dnsforwarder
	bool "Include DNSForwarder"
	default n
endef

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_shortcut-fe \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_hybla-cca \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_dnsforwarder

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
