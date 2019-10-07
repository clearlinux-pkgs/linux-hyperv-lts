#
# This is a special configuration of the Linux kernel, based on linux-hyperv
# package for long-term support
# This specialization allows us to optimize memory footprint and boot time.
#

Name:           linux-hyperv-lts
Version:        4.19.78
Release:        217
License:        GPL-2.0
Summary:        The Linux kernel
Url:            http://www.kernel.org/
Group:          kernel
Source0:        https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.78.tar.xz
Source1:        config
Source2:        cmdline

%define ktarget  hyperv-lts
%define kversion %{version}-%{release}.%{ktarget}

BuildRequires:  buildreq-kernel

Requires: systemd-bin
Requires: init-rdahead
Requires: linux-hyperv-lts-license = %{version}-%{release}

# don't strip .ko files!
%global __os_install_post %{nil}
%define debug_package %{nil}
%define __strip /bin/true

# kconfig: linux-hyperv-5.1.16-794

#cve.start cve patches from 0001 to 050
Patch0001: CVE-2019-12455.patch
Patch0002: CVE-2019-12456.patch
Patch0003: CVE-2019-12379.patch
#cve.end

#mainline: Mainline patches, upstream backport and fixes from 0051 to 0099
#mainline.end

#Serie.clr 01XX: Clear Linux patches
Patch0101: 0101-init-don-t-wait-for-PS-2-at-boot.patch
Patch0102: 0102-i8042-decrease-debug-message-level-to-info.patch
Patch0103: 0103-init-do_mounts-recreate-dev-root.patch
Patch0104: 0104-Increase-the-ext4-default-commit-age.patch
Patch0105: 0105-silence-rapl.patch
Patch0106: 0106-pci-pme-wakeups.patch
Patch0107: 0107-ksm-wakeups.patch
Patch0108: 0108-intel_idle-tweak-cpuidle-cstates.patch
Patch0109: 0109-xattr-allow-setting-user.-attributes-on-symlinks-by-.patch
Patch0110: 0110-init_task-faster-timerslack.patch
Patch0111: 0111-overload-on-wakeup.patch
Patch0112: 0112-bootstats-add-printk-s-to-measure-boot-time-in-more-.patch
Patch0113: 0113-fix-initcall-timestamps.patch
Patch0114: 0114-smpboot-reuse-timer-calibration.patch
Patch0115: 0115-raid6-add-Kconfig-option-to-skip-raid6-benchmarking.patch
Patch0116: 0116-Initialize-ata-before-graphics.patch
Patch0117: 0117-reduce-e1000e-boot-time-by-tightening-sleep-ranges.patch
Patch0118: 0118-Skip-synchronize_rcu-on-single-CPU-systems.patch
Patch0119: 0119-Make-a-few-key-drivers-probe-asynchronous.patch
Patch0120: 0120-sysrq-Skip-synchronize_rcu-if-there-is-no-old-op.patch
Patch0121: 0121-printk-end-of-boot.patch
Patch0122: 0122-Boot-with-rcu-expedite-on.patch
Patch0123: 0123-give-rdrand-some-credit.patch
Patch0124: 0124-print-starve.patch
Patch0125: 0125-increase-readahead-amounts.patch
Patch0126: 0126-remove-clear-ioapic.patch
Patch0127: 0127-Migrate-some-systemd-defaults-to-the-kernel-defaults.patch
Patch0128: 0128-use-lfence-instead-of-rep-and-nop.patch
Patch0129: 0129-do-accept-in-LIFO-order-for-cache-efficiency.patch
Patch0130: 0130-zero-extra-registers.patch
Patch0131: 0131-locking-rwsem-spin-faster.patch
#Serie.end

#Serie1.name WireGuard
#Serie1.git  https://git.zx2c4.com/WireGuard
#Serie1.cmt  d8179bf1ed9ecf0c7f9a78ceb0566a7e7b2f4497
#Serie1.tag  0.0.20190702
Patch1001: 1001-WireGuard-fast-modern-secure-kernel-VPN-tunnel.patch
#Serie1.end

#Serie2.name dysk
#Serie2.git  https://github.com/khenidak/dysk
#Serie2.dir  module
Patch2001: 2001-Add-dysk-driver.patch
Patch2002: 2002-dysk-let-compiler-handle-inlining.patch
Patch2003: 2003-Modify-Kconfig-Makefiles-to-support-dysk.patch
#Serie2.end

%description
The Linux kernel.

%package extra
License:        GPL-2.0
Summary:        The Linux kernel Hyper-V LTS extra files
Group:          kernel
Requires:       linux-hyperv-lts-license = %{version}-%{release}

%description extra
Linux kernel extra files

%package license
Summary: license components for the linux package.
Group: Default

%description license
license components for the linux package.

%prep
%setup -q -n linux-4.19.78

#cve.patch.start cve patches
%patch0001 -p1
%patch0002 -p1
%patch0003 -p1
#cve.patch.end

#mainline.patch.start Mainline patches, upstream backport and fixes
#mainline.patch.end

#Serie.patch.start Clear Linux patches
%patch0101 -p1
%patch0102 -p1
%patch0103 -p1
%patch0104 -p1
%patch0105 -p1
%patch0106 -p1
%patch0107 -p1
%patch0108 -p1
%patch0109 -p1
%patch0110 -p1
%patch0111 -p1
%patch0112 -p1
%patch0113 -p1
%patch0114 -p1
%patch0115 -p1
%patch0116 -p1
%patch0117 -p1
%patch0118 -p1
%patch0119 -p1
%patch0120 -p1
%patch0121 -p1
%patch0122 -p1
%patch0123 -p1
%patch0124 -p1
%patch0125 -p1
%patch0126 -p1
%patch0127 -p1
%patch0128 -p1
%patch0129 -p1
%patch0130 -p1
%patch0131 -p1
#Serie.patch.end

#Serie1.patch.start
%patch1001 -p1
#Serie1.patch.end

#Serie2.patch.start
%patch2001 -p1
%patch2002 -p1
%patch2003 -p1
#Serie2.patch.end

cp %{SOURCE1} .

%build
BuildKernel() {

    Target=$1
    Arch=x86_64
    ExtraVer="-%{release}.${Target}"

    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = ${ExtraVer}/" Makefile

    make O=${Target} -s mrproper
    cp config ${Target}/.config

    make O=${Target} -s ARCH=${Arch} olddefconfig
    make O=${Target} -s ARCH=${Arch} CONFIG_DEBUG_SECTION_MISMATCH=y %{?_smp_mflags} %{?sparse_mflags}
}

BuildKernel %{ktarget}

%install

InstallKernel() {

    Target=$1
    Kversion=$2
    Arch=x86_64
    KernelDir=%{buildroot}/usr/lib/kernel

    mkdir   -p ${KernelDir}
    install -m 644 ${Target}/.config    ${KernelDir}/config-${Kversion}
    install -m 644 ${Target}/System.map ${KernelDir}/System.map-${Kversion}
    install -m 644 ${Target}/vmlinux    ${KernelDir}/vmlinux-${Kversion}
    install -m 644 %{SOURCE2}           ${KernelDir}/cmdline-${Kversion}
    cp  ${Target}/arch/x86/boot/bzImage ${KernelDir}/org.clearlinux.${Target}.%{version}-%{release}
    chmod 755 ${KernelDir}/org.clearlinux.${Target}.%{version}-%{release}

    mkdir -p %{buildroot}/usr/lib/modules
    make O=${Target} -s ARCH=${Arch} INSTALL_MOD_PATH=%{buildroot}/usr modules_install

    rm -f %{buildroot}/usr/lib/modules/${Kversion}/build
    rm -f %{buildroot}/usr/lib/modules/${Kversion}/source

    # Kernel default target link
    ln -s org.clearlinux.${Target}.%{version}-%{release} %{buildroot}/usr/lib/kernel/default-${Target}
}

InstallKernel %{ktarget} %{kversion}

rm -rf %{buildroot}/usr/lib/firmware

mkdir -p %{buildroot}/usr/share/package-licenses/linux-hyperv-lts
cp COPYING %{buildroot}/usr/share/package-licenses/linux-hyperv-lts/COPYING
cp -a LICENSES/* %{buildroot}/usr/share/package-licenses/linux-hyperv-lts

%files
%dir /usr/lib/kernel
%dir /usr/lib/modules/%{kversion}
/usr/lib/kernel/config-%{kversion}
/usr/lib/kernel/cmdline-%{kversion}
/usr/lib/kernel/org.clearlinux.%{ktarget}.%{version}-%{release}
/usr/lib/kernel/default-%{ktarget}
/usr/lib/modules/%{kversion}/kernel
/usr/lib/modules/%{kversion}/modules.*

%files extra
%dir /usr/lib/kernel
/usr/lib/kernel/System.map-%{kversion}
/usr/lib/kernel/vmlinux-%{kversion}

%files license
%defattr(0644,root,root,0755)
/usr/share/package-licenses/linux-hyperv-lts
