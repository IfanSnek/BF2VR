// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#pragma once
#define XR_USE_GRAPHICS_API_D3D11
#include <d3d11.h>
#include <openxr/openxr.h>
#include <openxr/openxr_platform.h>
#include <atomic>
#include <vector>
#include <map>

namespace BF2VR {

class OpenXRService {
 public:
    static int Initialize();
    static void HandleStates();
    static void UpdatePose();
    static void WaitBeginFrame();
    static void BeforeDraw();
    static void AfterDraw();
    static void EndFrame();
    static int Uninitialize();

    static inline XrSession xrSession;
    static inline XrInstance xrInstance;
    static inline XrFrameState xrFrameState;
    static inline ID3D11RenderTargetView* uiRTV = nullptr;
    static inline std::map<uint32_t, std::vector<ID3D11RenderTargetView*>> xrRTVs;
    static inline uint32_t swapchainImageIndex;
    static inline uint32_t uiSwapchainImageIndex;
    static inline XrSpace xrSpace;
    static inline std::vector<XrView> xrViews;

    static inline bool xrRunning = false;
    static inline bool xrFocused = false;
    static inline bool xrExiting = false;
    static inline bool leftEye = true;

    static inline int swapchainWidth = 0;
    static inline int swapchainHeight = 0;

 private:
    static inline XrPosef hudPose = { {0, 0, 0, 1}, {0, 0, 0} };
    static inline std::vector<XrSwapchain> xrSwapchains;
    static inline std::vector<XrViewConfigurationView> xrConfigViews;
    static inline uint32_t xrViewCount;
    static inline std::vector<XrCompositionLayerProjectionView> xrProjectionViews;
    static inline XrCompositionLayerQuad xrUIView;
    static inline uint32_t xrProjectionViewCount;
    static inline XrEnvironmentBlendMode xrBlend;
};

}  // namespace BF2VR
