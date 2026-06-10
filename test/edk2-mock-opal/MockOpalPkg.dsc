## @file
#  MockOpalPkg — minimal standalone platform DSC for MockOpalDxe.
#
#  Built out-of-tree against a pinned upstream edk2 via PACKAGES_PATH (see
#  build.sh): the edk2 checkout is never patched, only MdePkg libraries are
#  consumed, and MdeLibs.dsc.inc supplies the toolchain-coupled library
#  instances (StackCheckLib, RegisterFilterLib), so bumping the edk2 tag
#  requires no changes here.
##

[Defines]
  PLATFORM_NAME           = MockOpalPkg
  PLATFORM_GUID           = a8d83876-64a0-11f1-9365-56433c165986
  PLATFORM_VERSION        = 0.1
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY        = Build/MockOpalPkg
  SUPPORTED_ARCHITECTURES = X64
  BUILD_TARGETS           = RELEASE|DEBUG
  SKUID_IDENTIFIER        = DEFAULT

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf

[Components]
  edk2-mock-opal/MockOpalDxe.inf
