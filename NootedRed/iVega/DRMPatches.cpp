//
//  DRMPatches.cpp
//  NootedRed
//
//  Created by Mac on 2024/11/22.
//  Copyright © 2024 ChefKiss. All rights reserved.
//

#include "DRMPatches.hpp"
#include <Headers/kern_api.hpp>
#include <Headers/kern_devinfo.hpp>
#include <IOKit/IODeviceTreeSupport.h>
#include <PrivateHeaders/NRed.hpp>

// 全局回调指针初始化为空
DRMPatches *DRMPatches::callback = nullptr;
uint8_t runTimes = 0;    // 运行次数计数器

// 初始化函数：设置回调指针
void DRMPatches::init() { callback = this; }

// 处理补丁器：主要的补丁应用逻辑
void DRMPatches::processPatcher(KernelPatcher &patcher) {
    // 检查运行模式是否正常
    if (!(lilu.getRunMode() & LiluAPI::RunningNormal)) {
        return;
    }

    // 设置硬件 ID
    auto *entry = IORegistryEntry::fromPath("/", gIODTPlane);
    if (entry) {
        DBGLOG("DYLD", "Setting hwgva-id to iMacPro1,1");
        entry->setProperty("hwgva-id", const_cast<char *>(kHwGvaId), arrsize(kHwGvaId));
        OSSafeReleaseNULL(entry);
    }

    // 设置页面验证钩子
  //  KernelPatcher::RouteRequest request {"_cs_validate_page", wrapCsValidatePage, this->orgCsValidatePage};

    PANIC_COND(!patcher.routeMultipleLong(KernelPatcher::KernelID, &request, 1), "DYLD",
       "Failed to route kernel symbols");
}

// 页面验证包装函数：处理内存页面验证和补丁应用
void DRMPatches::wrapCsValidatePage(vnode *vp, memory_object_t pager, memory_object_offset_t page_offset,
    const void *data, int *validated_p, int *tainted_p, int *nx_p) {
    // 调用原始页面验证函数
    FunctionCast(wrapCsValidatePage, callback->orgCsValidatePage)(vp, pager, page_offset, data, validated_p, tainted_p,
        nx_p);

    // 获取文件路径
    char path[PATH_MAX];
    int pathlen = PATH_MAX;
    if (vn_getpath(vp, path, &pathlen) != 0) { return; }

    // 处理非共享缓存路径
    if (!UserPatcher::matchSharedCachePath(path)) {
        if (LIKELY(strncmp(path, kCoreLSKDMSEPath, arrsize(kCoreLSKDMSEPath))) ||
            LIKELY(strncmp(path, kCoreLSKDPath, arrsize(kCoreLSKDPath)))) {
            return;
        }
        // 应用 CoreLSKD 流媒体补丁
        const DYLDPatch patch = {kCoreLSKDOriginal, kCoreLSKDPatched, "CoreLSKD streaming CPUID to Haswell"};
        patch.apply(const_cast<void *>(data), PAGE_SIZE);
        return;
    }

    // 应用 VideoToolbox DRM 机型检查补丁
    if (UNLIKELY(KernelPatcher::findAndReplace(const_cast<void *>(data), PAGE_SIZE, kVideoToolboxDRMModelOriginal,
            arrsize(kVideoToolboxDRMModelOriginal), BaseDeviceInfo::get().modelIdentifier, 20))) {
        DBGLOG("DYLD", "Applied 'VideoToolbox DRM model check' patch");
    }

    // 应用 AppleGVA 相关补丁
    const DYLDPatch patches[] = {
        {kAGVABoardIdOriginal, kAGVABoardIdPatched, "iMacPro1,1 spoof (AppleGVA)"},
        {kHEVCEncBoardIdOriginal, kHEVCEncBoardIdPatched, "iMacPro1,1 spoof (AppleGVAHEVCEncoder)"},
    };
    DYLDPatch::applyAll(patches, const_cast<void *>(data), PAGE_SIZE);

    // 检查设备类型
    auto model = BaseDeviceInfo::get().modelIdentifier;
    bool isMob = !strncmp(model, "MacBook", strlen("MacBook"));

    // 根据系统版本应用不同的 VA 补丁
    if (getKernelVersion() >= KernelVersion::Ventura) {
        // Ventura 及以上版本的 VA 补丁
        const DYLDPatch patches[] = {
            {kVAAcceleratorInfoIdentifyVenturaOriginal, kVAAcceleratorInfoIdentifyVenturaOriginalMask,
                kVAAcceleratorInfoIdentifyVenturaPatched, kVAAcceleratorInfoIdentifyVenturaPatchedMask,
                "VAAcceleratorInfo::identify"},
            {kVAFactoryCreateGraphicsEngineVenturaOriginal, kVAFactoryCreateGraphicsEngineVenturaOriginalMask,
                kVAFactoryCreateGraphicsEngineVenturaPatched, kVAFactoryCreateGraphicsEngineVenturaPatchedMask,
                "VAFactory::createGraphicsEngine"},
            {kVAFactoryCreateImageBltOriginal, kVAFactoryCreateImageBltMask, kVAFactoryCreateImageBltPatched,
                kVAFactoryCreateImageBltPatchedMask, "VAFactory::createImageBlt"},
            {kVAFactoryCreateVPVenturaOriginal, kVAFactoryCreateVPVenturaOriginalMask, kVAFactoryCreateVPVenturaPatched,
                kVAFactoryCreateVPVenturaPatchedMask, "VAFactory::create*VP"},
        };
        DYLDPatch::applyAll(patches, const_cast<void *>(data), PAGE_SIZE);
    } else {
        // 较早版本的 VA 补丁
        const DYLDPatch patches[] = {
            {kVAAcceleratorInfoIdentifyOriginal, kVAAcceleratorInfoIdentifyOriginalMask,
                kVAAcceleratorInfoIdentifyPatched, kVAAcceleratorInfoIdentifyPatchedMask,
                "VAAcceleratorInfo::identify"},
            {kVAFactoryCreateGraphicsEngineOriginal, kVAFactoryCreateGraphicsEngineOriginalMask,
                kVAFactoryCreateGraphicsEnginePatched, kVAFactoryCreateGraphicsEnginePatchedMask,
                "VAFactory::createGraphicsEngine"},
            {kVAFactoryCreateImageBltOriginal, kVAFactoryCreateImageBltMask, kVAFactoryCreateImageBltPatched,
                kVAFactoryCreateImageBltPatchedMask, "VAFactory::createImageBlt"},
            {kVAFactoryCreateVPOriginal, kVAFactoryCreateVPOriginalMask, kVAFactoryCreateVPPatched,
                kVAFactoryCreateVPPatchedMask, "VAFactory::create*VP"},
        };
        DYLDPatch::applyAll(patches, const_cast<void *>(data), PAGE_SIZE);
    }

    // 应用 VAAddrLibInterface 初始化补丁
    const DYLDPatch patch = {kVAAddrLibInterfaceInitOriginal, kVAAddrLibInterfaceInitOriginalMask,
        kVAAddrLibInterfaceInitPatched, kVAAddrLibInterfaceInitPatchedMask, "VAAddrLibInterface::init"};
    patch.apply(const_cast<void *>(data), PAGE_SIZE);

    // VCN1 特定补丁
    //if (NRed::callback->chipType >= ChipType::Renoir) { return; }

    // 应用 VCN1 相关补丁
    const DYLDPatch vcn1Patches[] = {
        {kWriteUvdNoOpOriginal, kWriteUvdNoOpPatched, "Vcn2DecCommand::writeUvdNoOp"},
        {kWriteUvdEngineStartOriginal, kWriteUvdEngineStartPatched, "Vcn2DecCommand::writeUvdEngineStart"},
        {kWriteUvdGpcomVcpuCmdOriginal, kWriteUvdGpcomVcpuCmdPatched, "Vcn2DecCommand::writeUvdGpcomVcpuCmdOriginal"},
        {kWriteUvdGpcomVcpuData0Original, kWriteUvdGpcomVcpuData0Patched,
            "Vcn2DecCommand::writeUvdGpcomVcpuData0Original"},
        {kWriteUvdGpcomVcpuData1Original, kWriteUvdGpcomVcpuData1Patched,
            "Vcn2DecCommand::writeUvdGpcomVcpuData1Original"},
        {kAddEncodePacketOriginal, kAddEncodePacketPatched, "Vcn2EncCommand::addEncodePacket"},
        {kAddSliceHeaderPacketOriginal, kAddSliceHeaderPacketMask, kAddSliceHeaderPacketPatched,
            kAddSliceHeaderPacketMask, "Vcn2EncCommand::addSliceHeaderPacket"},
        {kAddIntraRefreshPacketOriginal, kAddIntraRefreshPacketMask, kAddIntraRefreshPacketPatched,
            kAddIntraRefreshPacketMask, "Vcn2EncCommand::addIntraRefreshPacket"},
        {kAddContextBufferPacketOriginal, kAddContextBufferPacketPatched, "Vcn2EncCommand::addContextBufferPacket"},
        {kAddBitstreamBufferPacketOriginal, kAddBitstreamBufferPacketPatched,
            "Vcn2EncCommand::addBitstreamBufferPacket"},
        {kAddFeedbackBufferPacketOriginal, kAddFeedbackBufferPacketPatched, "Vcn2EncCommand::addFeedbackBufferPacket"},
        {kAddInputFormatPacketOriginal, kAddFormatPacketOriginalMask, kAddFormatPacketPatched,
            kAddFormatPacketPatchedMask, "Vcn2EncCommand::addInputFormatPacket"},
        {kAddOutputFormatPacketOriginal, kAddFormatPacketOriginalMask, kAddFormatPacketPatched,
            kAddFormatPacketPatchedMask, "Vcn2EncCommand::addOutputFormatPacket"},
    };
    DYLDPatch::applyAll(vcn1Patches, const_cast<void *>(data), PAGE_SIZE);
}
