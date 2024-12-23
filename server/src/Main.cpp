/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 01/15/2024
http://ahttp.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include "stdafx.h"
#include <conio.h>

#define AAPIDLL_USING

#include "Service.h"

#ifdef AAPIDLL_USING
#include <frame/asm/ITypedef_i.c>
#include <frame/asm/IAsynFrame_i.c>
#include <frame/asm/IAsynFileSystem_i.c>
#include <frame/asm/IAsynNetwork_i.c>
#include <frame/asm/INet_i.c>
#include <frame/asm/ISsl_i.c>
#endif

#ifdef AAPIDLL_USING
#pragma comment(lib, "asyncore_dll.lib")
#ifdef _DEBUG
#ifdef _DLL
#pragma comment(lib, "asynsdk_mini-MDd.lib")
#else
#pragma comment(lib, "asynsdk_mini-MTd.lib")
#endif
#else //
#ifdef _DLL
#pragma comment(lib, "asynsdk_mini-MD.lib")
#else
#pragma comment(lib, "asynsdk_mini-MT.lib")
#endif
#endif
#else
#ifdef _DLL
#pragma comment(lib, "asynframe-MD_lib.lib")
#else
#pragma comment(lib, "asynframe-MT_lib.lib")
#endif
#endif
STDAPI_(extern HRESULT) Initialize( /*[in ]*/IAsynMessageEvents *param1, /*[in ]*/IUnknown *param2 );
STDAPI_(extern HRESULT) Destory();
STDAPI_(extern InstancesManager *) GetInstancesManager();

static void ShowUsage(std::string name)
{
    std::string::size_type i = name.find_last_of("/\\");
    if( i != std::string::npos )
        name.erase(0, i + 1);

    printf("  Usage: %s [-4|6] configfile\n", name.c_str());
    printf("Options:\n");
    printf("      -4 Enforce IPv4\n");
    printf("      -6 Enforce IPv6\n");
}

int _tmain(int argc, _TCHAR *argv[])
{
    printf("Copyright (c) netsecsp 2012-2032, All rights reserved.\n");
    printf("Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated " STRING_UPDATETIME "\n");
    printf("http://ahttp.sf.net\n\n");

    char ipvx = AF_INET, *file = "config.txt";
    for(int i = 1; i < argc; ++ i)
    {
        if( strcmp(argv[i], "/?") == 0 || 
            strcmp(argv[i], "--help") == 0 )
        {
            file = 0;
            break;
        }

        if( argv[i][0] == '-' )
        {
            if( strcmp(argv[i], "-4") == 0 )
            {
                ipvx = AF_INET;
                continue;
            }
            if( strcmp(argv[i], "-6") == 0 )
            {
                ipvx = 23;
                continue;
            }
        }
        else
        {
            file = argv[i];
        }
    }

    if(!file )
    {
        ShowUsage(argv[0]);
        return 0;
    }

    asynsdk::CStringSetter fileconf(1, file);
    if( Initialize(NULL,&fileconf) != NO_ERROR )
    {
        printf("fail to Initialize asynframe\n");
        return 0;
    }

    do
    {
        InstancesManager *lpInstancesManager = GetInstancesManager();

        if( lpInstancesManager->Require(STRING_from_string(IN_AsynNetwork)) != S_OK )
        {
            printf("can't load plugin: %s\n", IN_AsynNetwork);
            break;
        }

        CComPtr<IAsynFrameThread> spAsynFrameThread;
        lpInstancesManager->NewInstance(0, TC_Iocp, IID_IAsynFrameThread, (IUnknown **)&spAsynFrameThread);

        std::unique_ptr<CService> pService(new CService(lpInstancesManager, spAsynFrameThread, ipvx));
        if( pService->Start() )
        {
            while(!_kbhit())
            {
                ::Sleep(100); //0.1sec
            }
        }
        pService->Shutdown();
    }while(0);

    if( Destory() != NO_ERROR )
    {
        printf("fail to Destory asynframe\n");
    }

    return 0;
}
