// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include "D3DService.h"
#include "Logging.h"
#include "OpenXRService.h"
#include "BF2Service.h"
#include "SDK.h"
#include <d3dcompiler.h>
#include <string>

namespace BF2VR {

void D3DService::DrawDetour(ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation) {
    if (!OpenXRService::xrRunning) {
        drawHook.call<void>(pContext, VertexCount, StartVertexLocation);
        return;
    }

    if (drawStage == COMPLETE) {
        // Start on left eye
        OpenXRService::WaitBeginFrame();
        drawStage = WAITED;
    }

    if (drawStage == WAITED || drawStage == DRAWN_L) {
        OpenXRService::BeforeDraw();
        drawStage = (drawStage == WAITED ? DRAWING_L : DRAWING_R);
    }

    // Aquire openxr RTV
    int CurrentEye = OpenXRService::leftEye ? 0 : 1;
    ID3D11RenderTargetView* xrRTV = OpenXRService::xrRTVs.at(CurrentEye).at(OpenXRService::swapchainImageIndex);
    if (xrRTV == nullptr) {
        return;
    }

    drawHook.call<void>(pContext, VertexCount, StartVertexLocation);

    pContext->OMSetRenderTargets(1, &xrRTV, nullptr);
    drawHook.call<void>(pContext, VertexCount, StartVertexLocation);
}

void D3DService::OnUIDraw() {
    if (!OpenXRService::xrRunning) {
        return;
    }

    // Aquire openxr RTV for UI
    ID3D11RenderTargetView* uiRTV = OpenXRService::xrRTVs.at(2).at(OpenXRService::uiSwapchainImageIndex);
    if (uiRTV == nullptr) {
        return;
    }
    pContext->OMSetRenderTargets(1, &uiRTV, nullptr);
}

HRESULT D3DService::PresentDetour(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags) {
    HRESULT toReturn = S_OK;

    // Not initialized yet or shutting down
    if (!OpenXRService::xrRunning) {
        return toReturn;
    }

    OpenXRService::HandleStates();

    // Switch eyes
    OpenXRService::leftEye = !OpenXRService::leftEye;
    OpenXRService::UpdatePose();

    // Only render to the flatscreen monitor on the left eye since we're using AER
    if (OpenXRService::leftEye) {
        toReturn = presentHook.call<HRESULT>(swapChain, syncInterval, flags);
    }

    if (drawStage == DRAWING_L || drawStage == DRAWING_R) {
        OpenXRService::AfterDraw();
        drawStage = (drawStage == DRAWING_L ? DRAWN_L : DRAWN_R);
    }

    if (drawStage == DRAWN_R) {
        OpenXRService::EndFrame();
        drawStage = COMPLETE;
    }

    // Clear the RTV for the HUD
    ID3D11RenderTargetView* uiRTV = OpenXRService::xrRTVs.at(2).at(OpenXRService::swapchainImageIndex);
    if (uiRTV != nullptr) {
        float bg[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        pContext->ClearRenderTargetView(uiRTV, bg);
    }

    return toReturn;
}

int D3DService::CaptureResources() {
    // Get our own window
    HWND ownWindow = FindWindowA("Frostbite", "STAR WARS Battlefront II");
    if (!ownWindow) {
        Logging::Log("[D3D11] Could not find own window. Was the mod loaded too early?");
        return -1;
    }

    auto featureLevel = D3D_FEATURE_LEVEL_11_0;

    DXGI_SWAP_CHAIN_DESC desc = {};
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 1;
    desc.Windowed = true;
    desc.OutputWindow = ownWindow;
    desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;

    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, &featureLevel, 1, D3D11_SDK_VERSION, &desc, &pSwapChain, nullptr, nullptr, nullptr))) {
        Logging::Log("[D3D11] Could not create dummy device for swapchain");
        return -1;
    }

    pDevice = DXRenderer::getDevice();
    if (!isValidPtr(pDevice)) {
        Logging::Log("[D3D11] Could not get device", (DWORD64)pDevice);
        return -1;
    }

    pContext = DXRenderer::getContext();
    if (!isValidPtr(pContext)) {
        Logging::Log("[D3D11] Could not get context");
        return -1;
    }

    return 0;
}

int D3DService::Initialize() {
    auto pTable = *reinterpret_cast<void***>(pSwapChain);
    presentHook = safetyhook::create_inline(reinterpret_cast<void*>(pTable[8]), reinterpret_cast<void*>(PresentDetour));

    auto pContextTable = *reinterpret_cast<void***>(pContext);
    drawHook = safetyhook::create_inline(reinterpret_cast<void*>(pContextTable[13]), reinterpret_cast<void*>(DrawDetour));

    safetyhook::MidHookFn drawUIFn = [](safetyhook::Context& ctx) {
        OnUIDraw();
    };
    uiHook = safetyhook::create_mid(reinterpret_cast<void*>(OFFSETUIDRAW), drawUIFn);

    Logging::Log("[D3D11] Hooked DirectX");
    return 0;
}

int D3DService::Uninitialize() {
    if (pVertexShader != nullptr) {
        pVertexShader->Release();
        pVertexShader = nullptr;
    }
    if (pPixelShader != nullptr) {
        pPixelShader->Release();
        pPixelShader = nullptr;
    }
    presentHook = {};
    drawHook = {};
    uiHook = {};

    Screen* screen = DXRenderer::getScreen();
    if (isValidPtr(screen)) {
        screen->bufferWidth = screen->anotherWidth;
        screen->bufferHeight = screen->anotherHeight;
    }

    return 0;
}

}  // namespace BF2VR
