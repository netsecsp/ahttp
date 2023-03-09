/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
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

#include "Downloader.h"

#ifdef AAPIDLL_USING
#include <frame/asm/ITypedef_i.c>
#include <frame/asm/IAsynFrame_i.c>
#include <frame/asm/IAsynFileSystem_i.c>
#include <frame/asm/IAsynNetwork_i.c>
#include <frame/asm/INet_i.c>
#include <frame/asm/IProxy_i.c>
#endif

#ifdef AAPIDLL_USING
#ifdef _DEBUG
#pragma comment(lib, "asynsdk_mini-MDd.lib")
#else
#pragma comment(lib, "asynsdk_mini-MD.lib")
#endif
#pragma comment(lib, "asyncore_dll.lib")
#else
#pragma comment(lib,"asynframe_lib.lib")
#endif
STDAPI_(extern HRESULT) Initialize( /*[in ]*/IAsynMessageEvents *param1, /*[in ]*/IUnknown *param2 );
STDAPI_(extern HRESULT) Destory();
STDAPI_(extern InstancesManager *) GetInstancesManager();

static void ShowUsage(const char *name)
{
    printf("usage: %s -4/6 url [offset]\n\texample: %s -4 http[s]://www.baidu.com/index.html\n\tplease check config.txt for proxy\n\n", name, name);
}

int _tmain(int argc, _TCHAR *argv[])
{
    printf("Copyright (c) netsecsp 2012-2032, All rights reserved.\n");
    printf("Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated " STRING_UPDATETIME "\n");
    printf("http://ahttp.sf.net\n\n");

    char *httpurl = "http://www.baidu.com/index.html", ipvx = '4', *pOffset = "0";
    for(int i = 1; i < argc; ++ i)
    {
        if( strcmp(argv[i], "/?") == 0 || 
            strcmp(argv[i], "--help") == 0 )
        {
            ShowUsage(argv[0]);
            return 0;
        }

        if( argv[i][0] == '-' )
        {
            ipvx = argv[i][1];
        }
        else
        {
            if( isdigit(argv[i][0]) )
				pOffset = argv[i];
            else
				httpurl = argv[i];
        }
    }
    
    if( Initialize(NULL, NULL) != NO_ERROR )
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
        lpInstancesManager->NewInstance(0, 0, IID_IAsynFrameThread, (void **)&spAsynFrameThread);

        HANDLE hNotify =  ::CreateEvent(0, 1, 0, 0);
        std::unique_ptr<CDownloader> pDownloader(new CDownloader(hNotify, lpInstancesManager, spAsynFrameThread, ipvx == '4'? 2 : 23));
		if (pDownloader->Start(httpurl, _atoi64(pOffset)))
        {
            while( WAIT_OBJECT_0 != ::WaitForSingleObject(hNotify, 0) &&
                   _kbhit() == 0 )
            {
                Sleep(100); //0.1sec
            }
        }
        pDownloader->Shutdown();

        ::CloseHandle( hNotify);
	}while(0);

    if( Destory() != NO_ERROR )
    {
        printf("fail to Destory asynframe\n");
    }

    return 0;
}
