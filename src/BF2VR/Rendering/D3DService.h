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
#include <d3d11.h>
#include <atomic>

#include <safetyhook.hpp>

namespace BF2VR {

class D3DService {
 public:
    static int Initialize();
    static int CaptureResources();
    static int Uninitialize();

    static inline ID3D11Device* pDevice;
    static inline ID3D11DeviceContext* pContext;
    static inline IDXGISwapChain* pSwapChain;
    static inline ID3D11RenderTargetView* uiRTV;
    static inline ID3D11Texture2D* uiBuffer;

 private:
    static inline SafetyHookInline presentHook;
    static HRESULT PresentDetour(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags);

    static inline SafetyHookInline drawHook;
    static void DrawDetour(ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation);

    static inline SafetyHookMid uiHook;
    static void OnUIDraw();

    static inline ID3D11VertexShader* pVertexShader = nullptr;
    static inline ID3D11PixelShader* pPixelShader = nullptr;

    enum DrawStage {
       WAITED,
       DRAWING_L,
       DRAWN_L,
       DRAWING_R,
       DRAWN_R,
       COMPLETE
    };

    static inline DrawStage drawStage = COMPLETE;
};

}  // namespace BF2VR

