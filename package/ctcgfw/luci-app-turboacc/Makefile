#
# Copyright (C) 2021 ImmortalWrt
# <https://immortalwrt.org>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-turboacc
PKG_VERSION:=1.0
PKG_RELEASE:=3

PKG_LICENSE:=GPL-3.0-only
PKG_LICENSE_FILE:=LICENSE
PKG_MAINTAINTER:=Tianling Shen <cnsztl@immortalwrt.org>

LUCI_TITLE:=LuCI support for Flow Offloading
LUCI_DEPENDS:= \
	+pdnsd-alt \
	+wget-ssl \
	+PACKAGE_TURBOACC_INCLUDE_OFFLOADING:kmod-ipt-offload \
	+PACKAGE_TURBOACC_INCLUDE_SHORTCUT_FE:kmod-fast-classifier \
	+PACKAGE_TURBOACC_INCLUDE_NATFLOW:kmod-natflow \
	+PACKAGE_TURBOACC_INCLUDE_BBR_CCA:kmod-tcp-bbr \
	+PACKAGE_TURBOACC_INCLUDE_DNSFORWARDER:dnsforwarder
LUCI_PKGARCH:=all

define Package/luci-app-turboacc/config
config PACKAGE_TURBOACC_INCLUDE_OFFLOADING
	bool "Include Offloading"
	depends on !LINUX_4_9 && \
		PACKAGE_TURBOACC_INCLUDE_SHORTCUT_FE=n && \
		PACKAGE_TURBOACC_INCLUDE_NATFLOW=n
	default y

config PACKAGE_TURBOACC_INCLUDE_SHORTCUT_FE
	bool "Include Shortcut FE"
	depends on PACKAGE_TURBOACC_INCLUDE_NATFLOW=n
	default y if LINUX_4_9

config PACKAGE_TURBOACC_INCLUDE_NATFLOW
	bool "Include NATFlow"
	default n

config PACKAGE_TURBOACC_INCLUDE_BBR_CCA
	bool "Include BBR CCA"
	default y

config PACKAGE_TURBOACC_INCLUDE_DNSFORWARDER
	bool "Include DNSForwarder"
	default n
endef

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_TURBOACC_INCLUDE_OFFLOADING \
	CONFIG_PACKAGE_TURBOACC_INCLUDE_SHORTCUT_FE \
	CONFIG_PACKAGE_TURBOACC_INCLUDE_NATFLOW \
	CONFIG_PACKAGE_TURBOACC_INCLUDE_BBR_CCA \
	CONFIG_PACKAGE_TURBOACC_INCLUDE_DNSFORWARDER

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
