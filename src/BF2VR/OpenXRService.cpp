// Copyright Ethan Porcaro

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include "OpenXRService.h"
#include "Logging.h"
#include "D3DService.h"
#include "Types.h"
#include "BF2Service.h"
#include "ActionsService.h"
#include <string>

namespace BF2VR {

    int OpenXRService::Initialize() {
        DXGI_SWAP_CHAIN_DESC desc;
        HRESULT hr = D3DService::pSwapChain->GetDesc(&desc);
        if (FAILED(hr)) {
            Logging::Log("[OPENXR] Could not get swapchain description", hr);
            return -1;
        }

        // Step 1: Enable necessary extensions
        XrInstanceCreateInfo createInfo = { XR_TYPE_INSTANCE_CREATE_INFO };
        createInfo.enabledExtensionCount = 1;
        const char* extensions[] = { XR_KHR_D3D11_ENABLE_EXTENSION_NAME };
        createInfo.enabledExtensionNames = extensions;

        // Step 2: Create the instance
        createInfo.applicationInfo.apiVersion = XR_CURRENT_API_VERSION;
        strcpy_s(createInfo.applicationInfo.applicationName, "Star Wars Battlefront II VR");
        XrResult result = xrCreateInstance(&createInfo, &xrInstance);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not create instance", result);
            return -1;
        }

        // Step 3: Load D3D11 extension
        PFN_xrGetD3D11GraphicsRequirementsKHR pfnGetD3D11GraphicsRequirementsKHR;
        result = xrGetInstanceProcAddr(xrInstance, "xrGetD3D11GraphicsRequirementsKHR",
            reinterpret_cast<PFN_xrVoidFunction*>(&pfnGetD3D11GraphicsRequirementsKHR));
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not load graphic requirements", result);
            return -1;
        }

        // Step 4: Configure HMD info and blend mode
        XrSystemGetInfo systemInfo = { XR_TYPE_SYSTEM_GET_INFO };
        systemInfo.formFactor = XR_FORM_FACTOR_HEAD_MOUNTED_DISPLAY;
        XrSystemId systemId;
        result = xrGetSystem(xrInstance, &systemInfo, &systemId);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not get system", result);
            return -1;
        }
        uint32_t blendModeCount = 0;
        result = xrEnumerateEnvironmentBlendModes(xrInstance, systemId, XR_VIEW_CONFIGURATION_TYPE_PRIMARY_STEREO,
            1, &blendModeCount, &xrBlend);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not enumerate environment blend modes", result);
            return -1;
        }

        // Step 5: Query graphics requirements
        XrGraphicsRequirementsD3D11KHR graphicsRequirements = { XR_TYPE_GRAPHICS_REQUIREMENTS_D3D11_KHR };
        result = pfnGetD3D11GraphicsRequirementsKHR(xrInstance, systemId, &graphicsRequirements);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not get D3D11 graphics requirements", result);
            return -1;
        }

        // Step 6: Bind to D3D11 device
        XrGraphicsBindingD3D11KHR graphicsBinding = { XR_TYPE_GRAPHICS_BINDING_D3D11_KHR };
        graphicsBinding.device = D3DService::pDevice;
        XrSessionCreateInfo sessionCreateInfo = { XR_TYPE_SESSION_CREATE_INFO };
        sessionCreateInfo.next = &graphicsBinding;
        sessionCreateInfo.systemId = systemId;
        result = xrCreateSession(xrInstance, &sessionCreateInfo, &xrSession);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not create OpenXR session", result);
            return -1;
        }

        // Step 7: Get view configuration views
        XrViewConfigurationType viewConfigType = XR_VIEW_CONFIGURATION_TYPE_PRIMARY_STEREO;
        result = xrEnumerateViewConfigurationViews(xrInstance, systemId, viewConfigType, 0, &xrViewCount, nullptr);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not enumerate view configuration views", result);
            return -1;
        }
        xrConfigViews.resize(xrViewCount, { XR_TYPE_VIEW_CONFIGURATION_VIEW });
        xrViews.resize(xrViewCount, { XR_TYPE_VIEW });
        result = xrEnumerateViewConfigurationViews(xrInstance, systemId, viewConfigType, xrViewCount, &xrViewCount,
            xrConfigViews.data());
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not enumerate view configuration views", result);
            return -1;
        }

        swapchainWidth = xrConfigViews[0].recommendedImageRectWidth;
        swapchainHeight = xrConfigViews[0].recommendedImageRectHeight;
        Logging::Log("[OPENXR] Width: " + std::to_string(swapchainWidth) + ", Height: " + std::to_string(swapchainHeight));


        // Step 8: Create swapchains (with one for the UI)
        for (uint32_t i = 0; i < xrViewCount + 1; i++) {
            // Create swapchain
            XrSwapchainCreateInfo swapchainCreateInfo = { XR_TYPE_SWAPCHAIN_CREATE_INFO };
            XrSwapchain swapchain;
            swapchainCreateInfo.arraySize = 1;
            swapchainCreateInfo.format = DXGI_FORMAT_R16G16B16A16_FLOAT;
            swapchainCreateInfo.width = swapchainWidth;
            swapchainCreateInfo.height = swapchainHeight;
            swapchainCreateInfo.mipCount = 1;
            swapchainCreateInfo.faceCount = 1;
            swapchainCreateInfo.sampleCount = 1;
            swapchainCreateInfo.usageFlags = XR_SWAPCHAIN_USAGE_SAMPLED_BIT | XR_SWAPCHAIN_USAGE_COLOR_ATTACHMENT_BIT;
            result = xrCreateSwapchain(xrSession, &swapchainCreateInfo, &swapchain);
            if (result != XR_SUCCESS) {
                Logging::Log("[OPENXR] Could not create swapchain", result);
                return -1;
            }

            // Get swapchain images
            uint32_t imageCount;
            result = xrEnumerateSwapchainImages(swapchain, 0, &imageCount, nullptr);
            if (result != XR_SUCCESS) {
                Logging::Log("[OPENXR] Could not enumerate swapchain image count", result);
                return -1;
            }
            std::vector<XrSwapchainImageD3D11KHR> swapchainImages(imageCount, { XR_TYPE_SWAPCHAIN_IMAGE_D3D11_KHR });
            result = xrEnumerateSwapchainImages(swapchain, imageCount, &imageCount,
                reinterpret_cast<XrSwapchainImageBaseHeader*>(swapchainImages.data()));
            if (result != XR_SUCCESS) {
                Logging::Log("[OPENXR] Could not enumerate swapchain images", result);
                return -1;
            }

            // Create RTVs
            std::vector<ID3D11RenderTargetView*> rtvs;
            for (const auto& swapchainImage : swapchainImages) {
                D3D11_RENDER_TARGET_VIEW_DESC rtvDesc = {};
                rtvDesc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
                rtvDesc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
                rtvDesc.Texture2D.MipSlice = 0;
                ID3D11RenderTargetView* rtv;
                HRESULT hr = D3DService::pDevice->CreateRenderTargetView(reinterpret_cast<ID3D11Resource*>(swapchainImage.texture), &rtvDesc, &rtv);
                if (FAILED(hr)) {
                    Logging::Log("[OPENXR] Could not create render target view", hr);
                    return -1;
                }
                rtvs.push_back(rtv);
            }
            xrSwapchains.push_back(swapchain);
            xrRTVs.insert(std::pair(i, rtvs));
        }

        // Step 9: Create app space
        XrReferenceSpaceCreateInfo spaceCreateInfo = { XR_TYPE_REFERENCE_SPACE_CREATE_INFO };
        spaceCreateInfo.referenceSpaceType = XR_REFERENCE_SPACE_TYPE_STAGE;
        spaceCreateInfo.poseInReferenceSpace = { {0, 0, 0, 1},
                                                {0, 0, 0} };
        result = xrCreateReferenceSpace(xrSession, &spaceCreateInfo, &xrSpace);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not create reference space", result);
            return -1;
        }
        Logging::Log("[OPENXR] OpenXR initialized");


        while (!xrRunning) {
            HandleStates();
        }

        return 0;
    }

    // This can return -1 in an emergency to shut down the mod
    void OpenXRService::HandleStates() {
        XrEventDataBuffer eventDataBuffer = { XR_TYPE_EVENT_DATA_BUFFER };
        XrResult result = xrPollEvent(xrInstance, &eventDataBuffer);

        while (result != XR_EVENT_UNAVAILABLE) {
            if (eventDataBuffer.type == XR_TYPE_EVENT_DATA_SESSION_STATE_CHANGED) {
                auto* event = reinterpret_cast<XrEventDataSessionStateChanged*>(&eventDataBuffer);

                if (event->state == XR_SESSION_STATE_READY && !xrRunning) {
                    Logging::Log("[OPENXR] Beginning session");
                    XrSessionBeginInfo sessionBeginInfo = { XR_TYPE_SESSION_BEGIN_INFO };
                    sessionBeginInfo.primaryViewConfigurationType = XR_VIEW_CONFIGURATION_TYPE_PRIMARY_STEREO;
                    XrResult result = xrBeginSession(xrSession, &sessionBeginInfo);
                    if (result != XR_SUCCESS) {
                        Logging::Log("[OPENXR] Could not begin OpenXR session", result);
                    }
                    xrRunning = true;
                    Logging::Log("[OPENXR] Session began");
                }

                if (event->state == XR_SESSION_STATE_STOPPING) {
                    Logging::Log("[OPENXR] Session stopping");


                    XrResult result = xrEndSession(xrSession);
                    if (result != XR_SUCCESS) {
                        Logging::Log("Could not end OpenXR session", result);
                    }
                    xrRunning = false;
                    Logging::Log("[OPENXR] Session stopped");
                }

                if (event->state == XR_SESSION_STATE_EXITING || event->state == XR_SESSION_STATE_LOSS_PENDING) {
                    Logging::Log("[OPENXR] Destroying resources");

                    if (xrRunning) {
                        Logging::Log("[OPENXR] Session was still running, stopping now");
                        XrResult result = xrEndSession(xrSession);
                        if (result != XR_SUCCESS) {
                            Logging::Log("Could not end OpenXR session", result);
                        }
                        xrRunning = false;
                        Logging::Log("[OPENXR] Session stopped");
                    }

                    if (isValidPtr(xrSession)) {
                        XrResult result = xrDestroySession(xrSession);
                        if (result != XR_SUCCESS) {
                            Logging::Log("[OPENXR] Could not destroy session. This should not happen and the game probably needs to be restarted", result);
                            return;
                        }
                    } else {
                        Logging::Log("[OPENXR] Could not destroy session since it is null. This should not happen and the game probably needs to be restarted");
                    }
                    if (isValidPtr(xrInstance)) {
                        result = xrDestroyInstance(xrInstance);
                        if (result != XR_SUCCESS) {
                            Logging::Log("[OPENXR] Could not destroy instance", result);
                        }
                        xrInstance = nullptr;
                    } else {
                        Logging::Log("[OPENXR] Could not destroy instance since it is null. This should not happen and the game probably needs to be restarted");
                    }

                    Logging::Log("[OPENXR] Destroyed resources");


                    // Ready to exit
                    xrExiting = true;
                    return;
                }

                if (event->state == XR_SESSION_STATE_FOCUSED) {
                    // Ready for input
                    xrFocused = true;
                }

                if (event->state == XR_SESSION_STATE_VISIBLE) {
                    // Currently not for input
                    xrFocused = false;
                }
            }

            eventDataBuffer.type = XR_TYPE_EVENT_DATA_BUFFER;
            result = xrPollEvent(xrInstance, &eventDataBuffer);
        }
    }

    void OpenXRService::UpdatePose() {
        // Sync actions
        if (xrFocused) {
            ActionsService::SyncActions();
        }

        int currentEye = leftEye ? 0 : 1;

        // Update HUD pose
        if (leftEye) {
            XrPosef hudTransform = xrViews.at(0).pose;
            Vec3 vecPos = Vec3(hudTransform.position.x, hudTransform.position.y, hudTransform.position.z);
            Vec4 quat = Vec4(hudTransform.orientation.x, hudTransform.orientation.y, hudTransform.orientation.z, hudTransform.orientation.w);
            Vec3 euler = eulerFromQuat(quat);
            Vec3 vecOffset = Vec3(.25f, .2f, -1.f);
            vecPos = rotateAround(vecOffset, vecPos, -euler.y);
            hudTransform.position = { vecPos.x, vecPos.y, vecPos.z };
            hudPose = hudTransform;
        }

        // Format the transform for BF2
        Matrix4 BFCameraTransform = fromOpenXR(xrViews.at(currentEye));

        // Calculate fov data
        auto [l, r, u, d] = xrViews.at(currentEye).fov;
        Matrix4 BFCameraProjection = fromFOV(l, r, u, d);


        // Set the transforms
        BF2Service::viewMatrix = BFCameraTransform;
        BF2Service::projMatrix = BFCameraProjection;

        BF2Service::gamepad.sThumbLX = ActionsService::walkValue.currentState.x * 32767;
        BF2Service::gamepad.sThumbLY = ActionsService::walkValue.currentState.y * 32767;

        BF2Service::gamepad.bLeftTrigger = (byte)(ActionsService::triggerValue[0].currentState * 255);
        BF2Service::gamepad.bRightTrigger = (byte)(ActionsService::triggerValue[1].currentState * 255);


        WORD buttons = 0;

        if (ActionsService::rollValue.currentState)
            buttons = buttons | 0x2000;
        if (ActionsService::jumpValue.currentState)
            buttons = buttons | 0x1000;
        if (ActionsService::basicValue.currentState)
            buttons = buttons | 0x8000;
        if (ActionsService::reloadValue.currentState)
            buttons = buttons | 0x4000;
        if (ActionsService::gripValue[0].currentState > 0.8)
            buttons = buttons | 0x0100;
        if (ActionsService::gripValue[1].currentState > 0.8)
            buttons = buttons | 0x0200;

        BF2Service::gamepad.wButtons = buttons;
    }

    void OpenXRService::WaitBeginFrame() {
        // Wait on the frame
        XrFrameWaitInfo frameWaitInfo = { XR_TYPE_FRAME_WAIT_INFO };
        xrFrameState = { XR_TYPE_FRAME_STATE };
        XrResult result = xrWaitFrame(xrSession, &frameWaitInfo, &xrFrameState);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not wait on frame", result);
            return;
        }

        // Get the view configuration views
        XrViewState viewState = { XR_TYPE_VIEW_STATE };
        XrViewLocateInfo locateInfo = { XR_TYPE_VIEW_LOCATE_INFO };
        locateInfo.viewConfigurationType = XR_VIEW_CONFIGURATION_TYPE_PRIMARY_STEREO;
        locateInfo.displayTime = xrFrameState.predictedDisplayTime;
        locateInfo.space = xrSpace;
        result = xrLocateViews(xrSession, &locateInfo, &viewState, xrViewCount, &xrProjectionViewCount, xrViews.data());
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not locate views", result);
            return;
        }
        xrProjectionViews.resize(xrProjectionViewCount);

        // Begin work on the frame
        XrFrameBeginInfo frameBeginInfo = { XR_TYPE_FRAME_BEGIN_INFO };
        result = xrBeginFrame(xrSession, &frameBeginInfo);
        if (result != XR_SUCCESS && result != XR_FRAME_DISCARDED) {
            Logging::Log("[OPENXR] Could not begin frame", result);
            return;
        }
    }

    void OpenXRService::BeforeDraw() {
        int currentEye = leftEye ? 0 : 1;

        // Prepare a projection view for the eye
        xrProjectionViews.at(currentEye) = { XR_TYPE_COMPOSITION_LAYER_PROJECTION_VIEW };
        xrProjectionViews.at(currentEye).pose = xrViews.at(currentEye).pose;
        xrProjectionViews.at(currentEye).fov = xrViews.at(currentEye).fov;
        xrProjectionViews.at(currentEye).subImage.swapchain = xrSwapchains.at(currentEye);
        xrProjectionViews.at(currentEye).subImage.imageRect.offset = {
            0,
            0
        };
        xrProjectionViews.at(currentEye).subImage.imageRect.extent = {
                (int32_t)swapchainWidth,
                (int32_t)swapchainHeight
        };

        // Prepare a projection view for the UI
        xrUIView = { XR_TYPE_COMPOSITION_LAYER_QUAD };
        xrUIView.subImage.swapchain = xrSwapchains.at(2);
        xrUIView.subImage.imageRect.offset = { 0, 0 };
        xrUIView.subImage.imageRect.extent = {
                (int32_t)swapchainWidth,
                (int32_t)swapchainHeight
        };
        xrUIView.layerFlags = XR_COMPOSITION_LAYER_BLEND_TEXTURE_SOURCE_ALPHA_BIT;
        xrUIView.eyeVisibility = XR_EYE_VISIBILITY_BOTH;
        xrUIView.space = xrSpace;
        xrUIView.size = { 1.0f, 1.0f };
        xrUIView.pose = hudPose;

        // Wait on the frame
        XrSwapchainImageAcquireInfo swapchainImageAcquireInfo = { XR_TYPE_SWAPCHAIN_IMAGE_ACQUIRE_INFO };
        XrResult result = xrAcquireSwapchainImage(xrSwapchains.at(currentEye), &swapchainImageAcquireInfo,
            &swapchainImageIndex);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not acquire swapchain image", result);
        }

        XrSwapchainImageWaitInfo swapchainImageWaitInfo = { XR_TYPE_SWAPCHAIN_IMAGE_WAIT_INFO };
        swapchainImageWaitInfo.timeout = XR_INFINITE_DURATION;
        result = xrWaitSwapchainImage(xrSwapchains.at(currentEye), &swapchainImageWaitInfo);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not wait on swapchain image", result);
        }

        // Wait on the UI
        swapchainImageAcquireInfo = { XR_TYPE_SWAPCHAIN_IMAGE_ACQUIRE_INFO };
        result = xrAcquireSwapchainImage(xrSwapchains.at(2), &swapchainImageAcquireInfo,
            &uiSwapchainImageIndex);
        if (result == XR_ERROR_CALL_ORDER_INVALID) {
            return;  // Ignore
        }
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not acquire swapchain image for UI", result);
        }

        swapchainImageWaitInfo = { XR_TYPE_SWAPCHAIN_IMAGE_WAIT_INFO };
        swapchainImageWaitInfo.timeout = XR_INFINITE_DURATION;
        result = xrWaitSwapchainImage(xrSwapchains.at(2), &swapchainImageWaitInfo);
        if (result != XR_SUCCESS && result != XR_ERROR_CALL_ORDER_INVALID) {
            Logging::Log("[OPENXR] Could not wait on swapchain image for UI", result);
        }
    }

    void OpenXRService::AfterDraw() {
        // Release the swapchain image
        int currentEye = leftEye ? 0 : 1;
        XrSwapchainImageReleaseInfo swapchainImageReleaseInfo = { XR_TYPE_SWAPCHAIN_IMAGE_RELEASE_INFO };
        XrResult result = xrReleaseSwapchainImage(xrSwapchains.at(currentEye), &swapchainImageReleaseInfo);
        if (result == XR_ERROR_CALL_ORDER_INVALID) {
            return;  // Ignore
        }
        if (result != XR_SUCCESS && result != XR_ERROR_CALL_ORDER_INVALID) {
            Logging::Log("[OPENXR] Could not release swapchain image", result);
            return;
        }

        // Release the swapchain image for UI
        if (leftEye) {
            swapchainImageReleaseInfo = { XR_TYPE_SWAPCHAIN_IMAGE_RELEASE_INFO };
            result = xrReleaseSwapchainImage(xrSwapchains.at(2), &swapchainImageReleaseInfo);
            if (result != XR_SUCCESS && result != XR_ERROR_CALL_ORDER_INVALID) {
                Logging::Log("[OPENXR] Could not release swapchain image for UI", result);
                return;
            }
        }
    }

    void OpenXRService::EndFrame() {
        // End the frame
        XrCompositionLayerProjection xrLayerProj = { XR_TYPE_COMPOSITION_LAYER_PROJECTION };
        xrLayerProj.space = xrSpace;
        xrLayerProj.viewCount = xrProjectionViewCount;
        xrLayerProj.views = xrProjectionViews.data();

        const auto xrLayer = reinterpret_cast<XrCompositionLayerBaseHeader*>(&xrLayerProj);
        const auto uiLayer = reinterpret_cast<XrCompositionLayerBaseHeader*>(&xrUIView);
        XrCompositionLayerBaseHeader* xrLayers[] = { xrLayer, uiLayer };

        XrFrameEndInfo frameEndInfo = { XR_TYPE_FRAME_END_INFO };
        frameEndInfo.displayTime = xrFrameState.predictedDisplayTime;
        frameEndInfo.environmentBlendMode = xrBlend;
        frameEndInfo.layerCount = (xrLayer == nullptr ? 0 : 1) + (uiLayer == nullptr ? 0 : 1);
        frameEndInfo.layers = xrLayers;

        XrResult result = xrEndFrame(xrSession, &frameEndInfo);
        if (result != XR_SUCCESS && result != XR_ERROR_CALL_ORDER_INVALID && result != XR_ERROR_LAYER_INVALID) {
            Logging::Log("[OPENXR] Could not end frame", result);
            return;
        }
    }

    int OpenXRService::Uninitialize() {
        xrRunning = false;

        XrResult result = xrRequestExitSession(xrSession);
        if (result != XR_SUCCESS) {
            Logging::Log("[OPENXR] Could not request OpenXR session exit", result);
            return -1;
        }
        while (!xrExiting) {
            HandleStates();
        }

        Logging::Log("[OPENXR] OpenXR quit");
        return 0;
    }
}  // namespace BF2VR
