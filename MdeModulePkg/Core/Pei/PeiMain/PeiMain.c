/** @file
  Pei Core Main Entry Point

Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PeiMain.h"

EFI_PEI_PPI_DESCRIPTOR  mMemoryDiscoveredPpi = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiMemoryDiscoveredPpiGuid,
  NULL
};

///
/// Pei service instance
///
EFI_PEI_SERVICES  gPs = {
  {
    PEI_SERVICES_SIGNATURE,
    PEI_SERVICES_REVISION,
    sizeof (EFI_PEI_SERVICES),
    0,
    0
  },
  // 这个函数通过GUID在PEI PPI数据库中安装一个接口。服务的目的是发布一个接口，其他各方可以使用该接口调用额外的PEIMs。
  PeiInstallPpi,
  // 这个函数通过GUID在PEI PPI数据库中重新安装一个接口。服务的目的是发布一个接口，其他各方可使用该接口用不同的接口替换协议数据库中同名的接口。
  PeiReInstallPpi,
  // locate一个给定的指定PPI。
  PeiLocatePpi,
  // 此函数安装通知服务，以便在安装或重新安装给定接口时回调该服务。
  // 服务的目的是发布一个接口，其他各方可以使用该接口来调用以后可能实现的其他PPIs。
  PeiNotifyPpi,

  // 该服务使PEIMs能够确定引导模式的当前值。
  PeiGetBootMode,
  // 该服务使PEIMs能够更新启动模式变量。
  PeiSetBootMode,

  // 获取指向HOB列表的指针。
  PeiGetHobList,
  // 向HOB列表中添加一个新的HOB。
  PeiCreateHob,

  // 通过索引搜索固件卷
  PeiFfsFindNextVolume,
  // 在固件卷中搜索下一个匹配文件。
  PeiFfsFindNextFile,
  // 在指定的文件中搜索下一个匹配部分。
  PeiFfsFindSectionData,

  // 该功能向PEI Foundation注册发现的内存配置。
  // 使用模型是发现永久内存的PEIM将调用此服务。
  // 这个例程将把发现的内存信息保存到PeiCore的私有数据中，并设置SwitchStackSignal标志。
  // 在分配了发现内存的PEIM后，PeiDispatcher将临时内存迁移到永久内存。
  PeiInstallPeiMemory,
  // 该服务的目的是发布一个接口，允许PEIMs分配由PEI Foundation管理的内存范围。
  PeiAllocatePages,
  // 内存池分配服务。在发现永久内存之前，将在临时内存中为池分配堆。通常，临时内存中的堆大小不会超过64K，因此可以分配的最大池大小是64K。
  PeiAllocatePool,
  (EFI_PEI_COPY_MEM)CopyMem,
  (EFI_PEI_SET_MEM)SetMem,

  // 状态代码报告程序的核心版本
  PeiReportStatusCode,
  // 核心版本的复位系统
  PeiResetSystem,

  // 这个默认的EFI_PEI_CPU_IO_PPI安装实例分配给EFI_PEI_SERVICE。PeiCore初始化时的CpuIo。
  &gPeiDefaultCpuIoPpi,
  // 将EFI_PEI_PCI_CFG2_PPI安装的默认实例分配给EFI_PEI_SERVICE。PeiCore初始化时的PciCfg。
  &gPeiDefaultPciCfg2Ppi,

  // 根据卷的名称查找卷中的文件
  PeiFfsFindFileByName,
  // 返回关于特定文件的信息。
  PeiFfsGetFileInfo,
  // 返回指定卷的信息。这个函数返回关于特定固件卷的信息，包括它的名称、类型、属性、起始地址和大小。
  PeiFfsGetVolumeInfo,
  // 当PEI Foundation发现永久内存时，这个程序使一个PEIM注册自己到映射。
  PeiRegisterForShadow,
  // 在指定的文件中搜索下一个匹配部分。
  PeiFfsFindSectionData3,
  // 返回关于特定文件的信息。
  PeiFfsGetFileInfo2,
  // 重置整个平台。
  PeiResetSystem2,
  PeiFreePages,
  PeiFfsFindSectionData4
};

/**
  Shadow PeiCore module from flash to installed memory.

  @param PrivateData    PeiCore's private data structure

  @return PeiCore function address after shadowing.
**/
PEICORE_FUNCTION_POINTER
ShadowPeiCore (
  IN PEI_CORE_INSTANCE  *PrivateData
  )
{
  EFI_PEI_FILE_HANDLE           PeiCoreFileHandle;
  EFI_PHYSICAL_ADDRESS          EntryPoint;
  EFI_STATUS                    Status;
  UINT32                        AuthenticationState;
  UINTN                         Index;
  EFI_PEI_CORE_FV_LOCATION_PPI  *PeiCoreFvLocationPpi;
  UINTN                         PeiCoreFvIndex;

  PeiCoreFileHandle = NULL;
  //
  // Default PeiCore is in BFV
  //
  PeiCoreFvIndex = 0;
  //
  // Find the PEI Core either from EFI_PEI_CORE_FV_LOCATION_PPI indicated FV or BFV
  //
  Status = PeiServicesLocatePpi (
             &gEfiPeiCoreFvLocationPpiGuid,
             0,
             NULL,
             (VOID **)&PeiCoreFvLocationPpi
             );
  if (!EFI_ERROR (Status) && (PeiCoreFvLocationPpi->PeiCoreFvLocation != NULL)) {
    //
    // If PeiCoreFvLocation present, the PEI Core should be found from indicated FV
    //
    for (Index = 0; Index < PrivateData->FvCount; Index++) {
      if (PrivateData->Fv[Index].FvHandle == PeiCoreFvLocationPpi->PeiCoreFvLocation) {
        PeiCoreFvIndex = Index;
        break;
      }
    }

    ASSERT (Index < PrivateData->FvCount);
  }

  //
  // Find PEI Core from the given FV index
  //
  Status = PrivateData->Fv[PeiCoreFvIndex].FvPpi->FindFileByType (
                                                    PrivateData->Fv[PeiCoreFvIndex].FvPpi,
                                                    EFI_FV_FILETYPE_PEI_CORE,
                                                    PrivateData->Fv[PeiCoreFvIndex].FvHandle,
                                                    &PeiCoreFileHandle
                                                    );
  ASSERT_EFI_ERROR (Status);

  //
  // Shadow PEI Core into memory so it will run faster
  //
  Status = PeiLoadImage (
             GetPeiServicesTablePointer (),
             *((EFI_PEI_FILE_HANDLE *)&PeiCoreFileHandle),
             PEIM_STATE_REGISTER_FOR_SHADOW,
             &EntryPoint,
             &AuthenticationState
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Compute the PeiCore's function address after shadowed PeiCore.
  // _ModuleEntryPoint is PeiCore main function entry
  //
  return (PEICORE_FUNCTION_POINTER)((UINTN)EntryPoint + (UINTN)PeiCore - (UINTN)_ModuleEntryPoint);
}

/**
  This routine is invoked by main entry of PeiMain module during transition
  from SEC to PEI. After switching stack in the PEI core, it will restart
  with the old core data.

  @param SecCoreDataPtr  Points to a data structure containing information about the PEI core's operating
                         environment, such as the size and location of temporary RAM, the stack location and
                         the BFV location.
  @param PpiList         Points to a list of one or more PPI descriptors to be installed initially by the PEI core.
                         An empty PPI list consists of a single descriptor with the end-tag
                         EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST. As part of its initialization
                         phase, the PEI Foundation will add these SEC-hosted PPIs to its PPI database such
                         that both the PEI Foundation and any modules can leverage the associated service
                         calls and/or code in these early PPIs
  @param Data            Pointer to old core data that is used to initialize the
                         core's data areas.
                         If NULL, it is first PeiCore entering.

**/

/**
  这个例程在从SEC过渡到PEI期间由PeiMain模块的主入口调用。
  在PEI核中切换堆栈后，它将用旧的核数据重新启动。

  @param SecCoreDataPtr  指向一个包含PEI核心操作环境信息的数据结构，例如临时RAM的大小和位置，堆栈位置和BFV位置。
                         
  @param PpiList        指向PEI核心最初要安装的一个或多个PPI描述符的列表。
                        空的PPI列表由单个描述符组成，其结束标记为EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST。
                        作为初始化阶段的一部分，PEI Foundation将把这些sec托管的PPIs添加到其PPI数据库中，
                        这样PEI Foundation和任何模块都可以利用这些早期PPIs中的相关服务调用和/或代码。
                        
  @param Data           指向旧核心数据的指针，用于初始化核心数据区域。如果为空，它是PeiCore第一次进入。
**/

VOID
EFIAPI
PeiCore (
  IN CONST EFI_SEC_PEI_HAND_OFF    *SecCoreDataPtr,
  IN CONST EFI_PEI_PPI_DESCRIPTOR  *PpiList,
  IN VOID                          *Data
  )
{
  //该结构为PeiMain的内部数据结构，维护运行PEI阶段所有需要的数据信息，包括PEI服务，FV数据空间，PEI模块的dispatch 状态，可使用的内存空间等
  PEI_CORE_INSTANCE               PrivateData;
  //保存着PEI核心运行环境的信息，如临时RAM的位置大小、堆栈位置和BFV位置。
  EFI_SEC_PEI_HAND_OFF            *SecCoreData;
  EFI_SEC_PEI_HAND_OFF            NewSecCoreData;
  EFI_STATUS                      Status;
  //临时使用的函数指针的联合(以节省堆栈空间)
  PEI_CORE_TEMP_POINTERS          TempPtr;
  PEI_CORE_INSTANCE               *OldCoreData;
  //EFI_PEI_CPU_IO_PPI提供一组内存和基于I/ o的服务。服务的视角是处理器的视角，而不是总线或系统的视角。
  EFI_PEI_CPU_IO_PPI              *CpuIo;
  //EFI_PEI_PCI_CFG_PPI接口用于在PCI根桥控制器后面抽象对PCI控制器的访问。
  EFI_PEI_PCI_CFG2_PPI            *PciCfg;
  //包含HOB生产者阶段使用的一般状态信息。该HOB必须是HOB列表中的第一个。
  EFI_HOB_HANDOFF_INFO_TABLE      *HandoffInformationTable;
  //这是一个可选的PPI，可由SEC或PEIM生产。如果存在，它提供一个服务来禁用临时RAM的使用。这种服务只能被PEIFoundation调用后，
  //从临时RAM过渡到永久RAM完成。这个PPI为系统架构提供了临时RAM迁移PPI的替代方案，允许临时RAM和永久RAM同时被启用和访问，而没有任何副作用。
  EFI_PEI_TEMPORARY_RAM_DONE_PPI  *TemporaryRamDonePpi;
  UINTN                           Index;

  //
  // Retrieve context passed into PEI Core
  //
  //
  // 检索传递到PEI核心的内容
  //
  OldCoreData = (PEI_CORE_INSTANCE *)Data;
  SecCoreData = (EFI_SEC_PEI_HAND_OFF *)SecCoreDataPtr;

  //
  // Perform PEI Core phase specific actions.
  //
  //
  // 执行PEI核心阶段的具体行动。
  //
  if (OldCoreData == NULL) {
    //
    // If OldCoreData is NULL, means current is the first entry into the PEI Core before memory is available.
    //
    //
    // 如果OldCoreData为NULL，表示current是在内存可用之前进入PEI核的第一个entry。
    //
    ZeroMem (&PrivateData, sizeof (PEI_CORE_INSTANCE));
    PrivateData.Signature = PEI_CORE_HANDLE_SIGNATURE;
    CopyMem (&PrivateData.ServiceTableShadow, &gPs, sizeof (gPs));
  } else {
    //
    // Memory is available to the PEI Core.  See if the PEI Core has been shadowed to memory yet.
    //
    //
    // PEI Core可以使用内存。看看Pei Core是否已经把gPs表拷贝到ServiceTableShadow里。
    // 当OldCoreData不为NULL时，但ShadowedPeiCore 为NULL时，这是第二次进入PeiCore， 切换HOB
    // 列表从堆中到物理内存中，更新传递类型的HOB 数据块记录物理内存的地址，某些PPI 地址空间记录在堆上，
    // 也需要切换到物理内存中。最后加载PeiMain 模块到物理内存中，并调用内存中的PeiCore 函数地址。
    //
    if (OldCoreData->ShadowedPeiCore == NULL) {
      //
      // Fixup the PeiCore's private data
      //
      //
      // 修复PeiCore的private数据
      // EFI_PEI_CPU_IO_PPI提供了一组基于内存和I/的服务。服务的视角是处理器的视角，而不是总线或系统的视角。
      //
      OldCoreData->Ps    = &OldCoreData->ServiceTableShadow;
      OldCoreData->CpuIo = &OldCoreData->ServiceTableShadow.CpuIo;
      if (OldCoreData->HeapOffsetPositive) {
        OldCoreData->HobList.Raw = (VOID *)(OldCoreData->HobList.Raw + OldCoreData->HeapOffset);
        if (OldCoreData->UnknownFvInfo != NULL) {
          OldCoreData->UnknownFvInfo = (PEI_CORE_UNKNOW_FORMAT_FV_INFO *)((UINT8 *)OldCoreData->UnknownFvInfo + OldCoreData->HeapOffset);
        }

        if (OldCoreData->CurrentFvFileHandles != NULL) {
          OldCoreData->CurrentFvFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->CurrentFvFileHandles + OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.PpiList.PpiPtrs != NULL) {
          OldCoreData->PpiData.PpiList.PpiPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.PpiList.PpiPtrs + OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs != NULL) {
          OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs + OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs != NULL) {
          OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs + OldCoreData->HeapOffset);
        }

        OldCoreData->Fv = (PEI_CORE_FV_HANDLE *)((UINT8 *)OldCoreData->Fv + OldCoreData->HeapOffset);
        for (Index = 0; Index < OldCoreData->FvCount; Index++) {
          if (OldCoreData->Fv[Index].PeimState != NULL) {
            OldCoreData->Fv[Index].PeimState = (UINT8 *)OldCoreData->Fv[Index].PeimState + OldCoreData->HeapOffset;
          }

          if (OldCoreData->Fv[Index].FvFileHandles != NULL) {
            OldCoreData->Fv[Index].FvFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->Fv[Index].FvFileHandles + OldCoreData->HeapOffset);
          }
        }

        OldCoreData->TempFileGuid    = (EFI_GUID *)((UINT8 *)OldCoreData->TempFileGuid + OldCoreData->HeapOffset);
        OldCoreData->TempFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->TempFileHandles + OldCoreData->HeapOffset);
      } else {
        OldCoreData->HobList.Raw = (VOID *)(OldCoreData->HobList.Raw - OldCoreData->HeapOffset);
        if (OldCoreData->UnknownFvInfo != NULL) {
          OldCoreData->UnknownFvInfo = (PEI_CORE_UNKNOW_FORMAT_FV_INFO *)((UINT8 *)OldCoreData->UnknownFvInfo - OldCoreData->HeapOffset);
        }

        if (OldCoreData->CurrentFvFileHandles != NULL) {
          OldCoreData->CurrentFvFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->CurrentFvFileHandles - OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.PpiList.PpiPtrs != NULL) {
          OldCoreData->PpiData.PpiList.PpiPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.PpiList.PpiPtrs - OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs != NULL) {
          OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.CallbackNotifyList.NotifyPtrs - OldCoreData->HeapOffset);
        }

        if (OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs != NULL) {
          OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs = (PEI_PPI_LIST_POINTERS *)((UINT8 *)OldCoreData->PpiData.DispatchNotifyList.NotifyPtrs - OldCoreData->HeapOffset);
        }

        OldCoreData->Fv = (PEI_CORE_FV_HANDLE *)((UINT8 *)OldCoreData->Fv - OldCoreData->HeapOffset);
        for (Index = 0; Index < OldCoreData->FvCount; Index++) {
          if (OldCoreData->Fv[Index].PeimState != NULL) {
            OldCoreData->Fv[Index].PeimState = (UINT8 *)OldCoreData->Fv[Index].PeimState - OldCoreData->HeapOffset;
          }

          if (OldCoreData->Fv[Index].FvFileHandles != NULL) {
            OldCoreData->Fv[Index].FvFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->Fv[Index].FvFileHandles - OldCoreData->HeapOffset);
          }
        }

        OldCoreData->TempFileGuid    = (EFI_GUID *)((UINT8 *)OldCoreData->TempFileGuid - OldCoreData->HeapOffset);
        OldCoreData->TempFileHandles = (EFI_PEI_FILE_HANDLE *)((UINT8 *)OldCoreData->TempFileHandles - OldCoreData->HeapOffset);
      }

      //
      // Fixup for PeiService's address
      //
      //
      // 修复PeiService的地址
      // 缓存指向PEI服务表的指针，该表由peiservicestlepointer以特定于CPU的方式指定，
      // 在平台初始化前efi初始化核心接口规范的CPU绑定部分中指定。该功能根据PI规范在KR7寄存器中设置PEI服务指针。
      SetPeiServicesTablePointer ((CONST EFI_PEI_SERVICES **)&OldCoreData->Ps);

      //
      // Initialize libraries that the PEI Core is linked against
      //
      //
      // 初始化PEI核心所链接的库
      //
      ProcessLibraryConstructorList (NULL, (CONST EFI_PEI_SERVICES **)&OldCoreData->Ps);

      //
      // Update HandOffHob for new installed permanent memory
      //
      // 为新安装的永久内存更新handffhob
      // EFI_HOB_HANDOFF_INFO_TABLE包含HOB生产者阶段所使用的一般状态信息。这个HOB必须是HOB列表中的第一个。
      //
      HandoffInformationTable = OldCoreData->HobList.HandoffInformationTable;
      if (OldCoreData->HeapOffsetPositive) {
        HandoffInformationTable->EfiEndOfHobList = HandoffInformationTable->EfiEndOfHobList + OldCoreData->HeapOffset;
      } else {
        HandoffInformationTable->EfiEndOfHobList = HandoffInformationTable->EfiEndOfHobList - OldCoreData->HeapOffset;
      }

      HandoffInformationTable->EfiMemoryTop        = OldCoreData->PhysicalMemoryBegin + OldCoreData->PhysicalMemoryLength;
      HandoffInformationTable->EfiMemoryBottom     = OldCoreData->PhysicalMemoryBegin;
      HandoffInformationTable->EfiFreeMemoryTop    = OldCoreData->FreePhysicalMemoryTop;
      HandoffInformationTable->EfiFreeMemoryBottom = HandoffInformationTable->EfiEndOfHobList + sizeof (EFI_HOB_GENERIC_HEADER);

      //
      // We need convert MemoryBaseAddress in memory allocation HOBs
      //
      ConvertMemoryAllocationHobs (OldCoreData);

      //
      // We need convert the PPI descriptor's pointer
      //
      // 我们需要转换PPI描述符的指针
      // 该函数负责将PPI指针从临时内存堆栈迁移到PEI安装的内存中。
      //
      ConvertPpiPointers (SecCoreData, OldCoreData);

      //
      // After the whole temporary memory is migrated, then we can allocate page in
      // permanent memory.
      //
      // 在迁移了整个临时内存之后，我们可以在永久内存中分配页。
      // 更新状态标志位，表示PEI Memory 已实装
      //
      OldCoreData->PeiMemoryInstalled = TRUE;

      //
      // Indicate that PeiCore reenter
      //
      // Indicate that PeiCore reenter
      // 指示PeiCore重新进入,更新状态标志位
      //
      OldCoreData->PeimDispatcherReenter = TRUE;
      //PcdLoadModuleAtFixAddressEnable是启用/禁用固定地址加载模块特性的标志。
      //BootMode是在HOB产生阶段确定的系统启动模式。 #define BOOT_ON_S3_RESUME 0x11
      if ((PcdGet64 (PcdLoadModuleAtFixAddressEnable) != 0) && (OldCoreData->HobList.HandoffInformationTable->BootMode != BOOT_ON_S3_RESUME)) {
        //
        // if Loading Module at Fixed Address is enabled, allocate the PEI code memory range usage bit map array.
        // Every bit in the array indicate the status of the corresponding memory page available or not
        //
        // 如果启用了固定地址加载模块，则分配PEI代码内存范围使用 bit map数组。
        // 数组中的每个位都表示对应的内存页是否可用
        //
        OldCoreData->PeiCodeMemoryRangeUsageBitMap = AllocateZeroPool (((PcdGet32 (PcdLoadFixAddressPeiCodePageNumber)>>6) + 1)*sizeof (UINT64));
      }

      //
      // Shadow PEI Core. When permanent memory is available, shadow
      // PEI Core and PEIMs to get high performance.
      //
      // Shadow PEI Core. When permanent memory is avaiable, shadow PEI Core and PEIMs to get high performance.
      // Shadow PEI核心。当永久存储器可用时，对PEI核和PEIMs进行Shadow处理，以获得高性能。
      // 所谓BIOS shadow实质上就是将BIOS程序从设备拷贝到内存中，只是不管在设备还是在内存中，两者用到的地址是相同的，
      // 所以对正在运行的程序来说，并没法看出什么区别来，所以叫shadow，只是通过控制PAM寄存器让其定向到不同的设备上。
      // 对BIOS程序进行shadow的主要目的就是为了实现性能的提升，因为BIOS刚开始执行的时候，内存并没有初始化，程序没法直接放到内存中。
      OldCoreData->ShadowedPeiCore = (PEICORE_FUNCTION_POINTER)(UINTN)PeiCore;
      // 表示是否在内存准备好后，在S3启动路径上shadow PEIM。 PcdShadowPeimOnBoot|TRUE|BOOLEAN|0x30001029
      if (PcdGetBool (PcdMigrateTemporaryRamFirmwareVolumes) ||
          ((HandoffInformationTable->BootMode == BOOT_ON_S3_RESUME) && PcdGetBool (PcdShadowPeimOnS3Boot)) ||
          ((HandoffInformationTable->BootMode != BOOT_ON_S3_RESUME) && PcdGetBool (PcdShadowPeimOnBoot)))
      {
        //ShadowPeiCore():Shadow PeiCore模块从flash安装到内存。
        OldCoreData->ShadowedPeiCore = ShadowPeiCore (OldCoreData);
      }

      //
      // PEI Core has now been shadowed to memory.  Restart PEI Core in memory.
      //
      // PE1I核心现在被shadow到内存。重新启动内存中的PEI核。
      // SecCoreData:指向一个包含SEC到PEI转换数据的数据结构，如临时RAM的大小和位置，堆栈位置和BFV位置。
      // PpiList:指向PEI核心最初要安装的一个或多个PPI描述符的列表。空的PPI列表由单个描述符组成，
      //         其结束标记为EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST。
      //         作为初始化阶段的一部分，PEI Foundation将把这些sec托管的PPIs添加到其PPI数据库中，
      //         这样PEI Foundation和任何模块都可以利用这些早期PPIs中的相关服务调用和/或代码。
      // OldCoreData:指向旧核心数据的指针，用于初始化核心数据区域。
      OldCoreData->ShadowedPeiCore (SecCoreData, PpiList, OldCoreData);

      //
      // Should never reach here.
      //
      ASSERT (FALSE);
      CpuDeadLoop ();

      UNREACHABLE ();
    }

    //
    // Memory is available to the PEI Core and the PEI Core has been shadowed to memory.
    //
    // 内存对PEI核是可用的，而PEI核已经被shadow在内存中。
    //
    CopyMem (&NewSecCoreData, SecCoreDataPtr, sizeof (NewSecCoreData));
    SecCoreData = &NewSecCoreData;

    CopyMem (&PrivateData, OldCoreData, sizeof (PrivateData));

    CpuIo  = (VOID *)PrivateData.ServiceTableShadow.CpuIo;
    PciCfg = (VOID *)PrivateData.ServiceTableShadow.PciCfg;

    CopyMem (&PrivateData.ServiceTableShadow, &gPs, sizeof (gPs));

    PrivateData.ServiceTableShadow.CpuIo  = CpuIo;
    PrivateData.ServiceTableShadow.PciCfg = PciCfg;
  }

  //
  // Cache a pointer to the PEI Services Table that is either in temporary memory or permanent memory
  //
  // 缓存一个指向PEI Services表的指针，该表在临时内存或永久内存中
  //
  PrivateData.Ps = &PrivateData.ServiceTableShadow;

  //
  // Save PeiServicePointer so that it can be retrieved anywhere.
  //
  // 保存PeiServicePointer，以便可以在任何地方检索它。
  // 缓存指向PEI服务表的指针，该表由peiservicestlepointer以特定于CPU的方式指定，
  // 在平台初始化前efi初始化核心接口规范的CPU绑定部分中指定。该函数根据PI规范将PEI服务的指针设置在IDT表的前面。
  SetPeiServicesTablePointer ((CONST EFI_PEI_SERVICES **)&PrivateData.Ps);

  //
  // Initialize libraries that the PEI Core is linked against
  //
  // 初始化PEI核心所链接的库
  ProcessLibraryConstructorList (NULL, (CONST EFI_PEI_SERVICES **)&PrivateData.Ps);

  //
  // Initialize PEI Core Services
  //
  InitializeMemoryServices (&PrivateData, SecCoreData, OldCoreData);

  //
  // Update performance measurements
  //
  // 更新性能测量
  // PERF_START 和END之间用于测量时间，SEC阶段运行多长时间可以通过该功能实现统计打印。
  if (OldCoreData == NULL) {
    PERF_EVENT ("SEC"); // Means the end of SEC phase.

    //
    // If first pass, start performance measurement.
    //
    // 如果第一次通过，就开始进行性能评估。
    PERF_CROSSMODULE_BEGIN ("PEI");
    PERF_INMODULE_BEGIN ("PreMem");
  } else {
    PERF_INMODULE_END ("PreMem");
    PERF_INMODULE_BEGIN ("PostMem");
  }

  //
  // Complete PEI Core Service initialization
  //
  // 完成PEI核心服务初始化
  InitializeSecurityServices (&PrivateData.Ps, OldCoreData);
  InitializeDispatcherData (&PrivateData, OldCoreData, SecCoreData);
  InitializeImageServices (&PrivateData, OldCoreData);

  //
  // Perform PEI Core Phase specific actions
  //
  // 执行PEI核心阶段的具体行动
  if (OldCoreData == NULL) {
    //
    // Report Status Code EFI_SW_PC_INIT
    //
    REPORT_STATUS_CODE (
      EFI_PROGRESS_CODE,
      (EFI_SOFTWARE_PEI_CORE | EFI_SW_PC_INIT)
      );

    //
    // If SEC provided the PpiList, process it.
    //
    // 如果SEC向PEI提供了任何PPI服务，安装它们。
    if (PpiList != NULL) {
      ProcessPpiListFromSec ((CONST EFI_PEI_SERVICES **)&PrivateData.Ps, PpiList);
    }
  } else {
    if (PcdGetBool (PcdMigrateTemporaryRamFirmwareVolumes)) {
      //
      // When PcdMigrateTemporaryRamFirmwareVolumes is TRUE, alway shadow all
      // PEIMs no matter the condition of PcdShadowPeimOnBoot and PcdShadowPeimOnS3Boot
      //
      DEBUG ((DEBUG_VERBOSE, "PPI lists before temporary RAM evacuation:\n"));
      DumpPpiList (&PrivateData);

      //
      // Migrate installed content from Temporary RAM to Permanent RAM
      //
      EvacuateTempRam (&PrivateData, SecCoreData);

      DEBUG ((DEBUG_VERBOSE, "PPI lists after temporary RAM evacuation:\n"));
      DumpPpiList (&PrivateData);
    }

    //
    // Try to locate Temporary RAM Done Ppi.
    //
    // 从临时RAM过渡到永久RAM完成后，禁用临时RAM的使用。
    Status = PeiServicesLocatePpi (
               &gEfiTemporaryRamDonePpiGuid,
               0,
               NULL,
               (VOID **)&TemporaryRamDonePpi
               );
    if (!EFI_ERROR (Status)) {
      //
      // Disable the use of Temporary RAM after the transition from Temporary RAM to Permanent RAM is complete.
      //
      TemporaryRamDonePpi->TemporaryRamDone ();
    }

    //
    // Alert any listeners that there is permanent memory available
    //
    // 提醒任何侦听器有可用的永久内存
    // 如果设置了PcdPerformanceLibraryPropertyMask的PERFORMANCE_LIBRARY_PROPERTY_MEASUREMENT_ENABLED位，
    // 则调用StartPerformanceMeasurement()。
    PERF_INMODULE_BEGIN ("DisMem");
    Status = PeiServicesInstallPpi (&mMemoryDiscoveredPpi);

    //
    // Process the Notify list and dispatch any notifies for the Memory Discovered PPI
    //
    // 处理Notify列表并为发现的PPI分配任何通知
    // 检查刚刚被分派的PEIM是否导致任何通知被安装。如果是，则go处理与以前安装的PPIs匹配的任何分派级别通知。
    // 使用“while”而不是“if”，因为DispatchNotify可以修改DispatchListEnd(使用NotifyPpi)，所以我们必须迭代直到相同。
    ProcessDispatchNotifyList (&PrivateData);

    PERF_INMODULE_END ("DisMem");
  }

  //
  // Call PEIM dispatcher
  //
  // pei dispatcher 为pei core 的一部分，用来搜寻和执行peim.
  PeiDispatcher (SecCoreData, &PrivateData);

  if (PrivateData.HobList.HandoffInformationTable->BootMode != BOOT_ON_S3_RESUME) {
    //
    // Check if InstallPeiMemory service was called on non-S3 resume boot path.
    //
    // 检查InstallPeiMemory服务是否在非s3恢复引导路径上被调用。
    ASSERT (PrivateData.PeiMemoryInstalled == TRUE);
  }

  //
  // Measure PEI Core execution time.
  //
  PERF_INMODULE_END ("PostMem");

  //
  // Lookup DXE IPL PPI
  //
  Status = PeiServicesLocatePpi (
             &gEfiDxeIplPpiGuid,
             0,
             NULL,
             (VOID **)&TempPtr.DxeIpl
             );
  ASSERT_EFI_ERROR (Status);

  if (EFI_ERROR (Status)) {
    //
    // Report status code to indicate DXE IPL PPI could not be found.
    //
    // 报告状态代码以指示无法找到DXE IPL PPI。
    REPORT_STATUS_CODE (
      EFI_ERROR_CODE | EFI_ERROR_MAJOR,
      (EFI_SOFTWARE_PEI_CORE | EFI_SW_PEI_CORE_EC_DXEIPL_NOT_FOUND)
      );
    CpuDeadLoop ();
  }

  //
  // Enter DxeIpl to load Dxe core.
  //
  // 输入DxeIpl加载Dxe core。
  DEBUG ((DEBUG_INFO, "DXE IPL Entry\n"));
  Status = TempPtr.DxeIpl->Entry (
                             TempPtr.DxeIpl,
                             &PrivateData.Ps,
                             PrivateData.HobList
                             );
  //
  // Should never reach here.
  //
  ASSERT_EFI_ERROR (Status);
  CpuDeadLoop ();
  
  // 信号编译器和分析程序，该调用是不可达的。由编译器删除超过这一点的代码。
  UNREACHABLE ();
}
