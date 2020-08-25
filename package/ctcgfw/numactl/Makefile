#
# Copyright (C) 2019 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=numactl
PKG_VERSION:=2.0.13
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/numactl/numactl/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=97ee012b2f294903530424b4ff7f28bcaad6a356897ce8777383f87e5c2e325d
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=CN_SZTL <cnsztl@project-openwrt.eu.org>

PKG_INSTALL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/default
	TITLE:=NUMA support for Linux
	URL:=https://github.com/numactl/numactl
endef

define Package/$(PKG_NAME)/description/default
	Simple NUMA policy support. It consists of a numactl program to run
	other programs with a specific NUMA policy and a libnuma shared library
	("NUMA API") to set NUMA policy in applications.
endef

define Package/numactl
	$(Package/$(PKG_NAME)/default)
	SECTION:=net
	CATEGORY:=Network
	TITLE+= (Utilities)
	DEPENDS:=+libnuma +libpthread +librt
endef

Package/numactl/description = $(Package/$(PKG_NAME)/description/default)

define Package/libnuma
	$(Package/$(PKG_NAME)/default)
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE+= (libraries)
	DEPENDS:=+zlib
endef

Package/libnuma/description = $(Package/$(PKG_NAME)/description/default)

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnuma.{*a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/numa.pc $(1)/usr/lib/pkgconfig/
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/{numa,numacompat1,numaif}.h $(1)/usr/include/
endef

define Package/numactl/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/memhog $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/migratepages $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/migspeed $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/numactl $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/numademo $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/numastat $(1)/usr/bin/
endef

define Package/libnuma/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libnuma.{*a,so*} $(1)/usr/lib/
endef

$(eval $(call BuildPackage,numactl))
$(eval $(call BuildPackage,libnuma))
