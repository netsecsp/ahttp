#ifndef __SERVICE_H__
#define __SERVICE_H__
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
#include <map>
#include <frame/AsynNetwork_internal.h>
#include <frame/AsynFile_internal.h>
#include <frame/asm/INet.h>
#include "Tranfile.h"
#include "web.h"
#include "setting.h"
using namespace asynsdk;

class CService : public asyn_message_events_impl
{
public:
    CService(InstancesManager *lpInstanceManager, IAsynFrameThread *lpAsynFrameThread, uint32_t af = AF_INET)
        : m_af(af), m_setsfile("config.txt")
    {
        m_spInstanceManager = lpInstanceManager;
        m_spAsynFrameThread = lpAsynFrameThread;
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork), IID_IAsynNetwork, (void **)&m_spAsynNetwork);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);

        m_mapMimes[".ts"  ] = "video/MP2T";
        m_mapMimes[".flv" ] = "video/x-flv";
        m_mapMimes[".m4v" ] = "video/x-m4v";
        m_mapMimes[".3gpp"] = "video/3gpp";
        m_mapMimes[".3gp" ] = "video/3gpp";
        m_mapMimes[".mp4" ] = "video/mp4";
        m_mapMimes[".aac" ] = "audio/x-aac";
        m_mapMimes[".mp3" ] = "audio/mpeg";
        m_mapMimes[".m4a" ] = "audio/x-m4a";
        m_mapMimes[".ogg" ] = "audio/ogg";
        m_mapMimes[".m3u8"] = "application/vnd.apple.mpegurl"; // application/x-mpegURL
        m_mapMimes[".rss" ] = "application/rss+xml";
        m_mapMimes[".json"] = "application/json";
        m_mapMimes[".swf" ] = "application/x-shockwave-flash";
        m_mapMimes[".doc" ] = "application/msword";
        m_mapMimes[".zip" ] = "application/zip";
        m_mapMimes[".rar" ] = "application/x-rar-compressed" ;
        m_mapMimes[".xml" ] = "text/xml";
        m_mapMimes[".html"] = "text/html";
        m_mapMimes[".js"  ] = "text/javascript";
        m_mapMimes[".css" ] = "text/css";
        m_mapMimes[".ico" ] = "image/x-icon";
        m_mapMimes[".png" ] = "image/png";
        m_mapMimes[".jpeg"] = "image/jpeg";
        m_mapMimes[".jpg" ] = "image/jpeg";
        m_mapMimes[".gif" ] = "image/gif";
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CService)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lParam2, IKeyvalSetter **ppKeyval );

public:
    bool Start()
    {
        if( m_spInstanceManager->Require(STRING_from_string(IN_AsynFileSystem)) != S_OK )
        {
            printf("can't load plugin: %s\n", IN_AsynFileSystem);
            return false;
        }

        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynFileSystem), IID_IAsynFileSystem, (void **)&m_spAsynFileSystem);

        //设置全局发送速度: IAsynNetwork, B/s
        CComPtr<ISpeedController> spGlobalSpeedController;
        CComPtr<IObjectHolder   > spObjectHolder;
        m_spAsynNetwork->QueryInterface(IID_IObjectHolder, (void **)&spObjectHolder);
        spObjectHolder->Get(Io_send, 0, IID_ISpeedController, (void **)&spGlobalSpeedController);
        spGlobalSpeedController->SetMaxSpeed(m_setsfile.get_long("globals", "max_sendspeed", -1));

        m_pWebsite.reset(new CWeb(m_spAsynFrameThread, m_setsfile.get_string("website", "home")));
        m_pWebsite->Start(m_spInstanceManager, m_setsfile.get_long("website", "active_detech_files_changed", 1));

        if( m_setsfile.is_exist("ssl", "cert"))
        {// for ssl
            const std::string &file = m_setsfile.get_string("ssl", "cert");
            FILE *f = 0; errno_t hr = fopen_s(&f, file.c_str(), "rb");
            if( f )
            {
                BYTE temp[4096];
                int  size = fread(temp, 1, sizeof(temp), f);
                fclose(f);
                if( size > 0 )
                {
                    m_cert_p12.assign((char*)temp, size);
                    m_password = m_setsfile.get_string("ssl", "password");
                }
            }
            else
            {
                printf("open cert.p12[%s], error: %d\n", file.c_str(), (int)hr);
            }
        }

        CComPtr<IThreadPool> threadpool;
        m_spInstanceManager->NewInstance(0, 0, IID_IThreadPool, (void**)&threadpool);
        
        PORT tcpport = (PORT)m_setsfile.get_long("tcp", "port", 80);
        if( tcpport )
        {// check [tcp]
            CComPtr<IAsynTcpSocketListener> spAsynInnSocketListener;
            m_spAsynNetwork->CreateAsynTcpSocketListener(STRING_EX::null, &spAsynInnSocketListener);

            CComPtr<IAsynRawSocket        > spAsynPtlSocket;
            m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("http"), (IUnknown **)&spAsynInnSocketListener.p, STRING_from_string("tcp/" + m_setsfile.get_string("globals", "version", "1.1")), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: http\n");
                return false;
            }
            spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocketListener, (void**)&m_spAsynTcpSocketListener[0]);

            HRESULT r0 = m_spAsynTcpSocketListener[0]->Set (DT_SetThreadpool, 0, threadpool); //设置接入线程池

            HRESULT r1 = m_spAsynTcpSocketListener[0]->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);
            HRESULT r2 = m_spAsynTcpSocketListener[0]->Bind(STRING_EX::null, tcpport, FALSE, NULL); //同步bind
            if( r2 != 0 )
            {
                printf("bind *:%-4d[%s], error: %d\n", tcpport, m_af == AF_INET? "ipv4" : "ipv6", r2);
                return false;
            }

            if(!tcpport ) m_spAsynTcpSocketListener[0]->GetSockAddress(0, 0, &tcpport, 0);
            printf("tcp.listen *:%-4d[%s]\n", tcpport, m_af == AF_INET? "ipv4" : "ipv6");
        }

        PORT sslport = (PORT)m_setsfile.get_long("ssl", "port");
        if(!m_cert_p12.empty() &&
            sslport )
        {// check [ssl]
            CComPtr<IAsynTcpSocketListener> spAsynInnSocketListener;
            m_spAsynNetwork->CreateAsynTcpSocketListener(STRING_EX::null, &spAsynInnSocketListener);

            CComPtr<IAsynRawSocket        > spAsynPtlSocket;
            m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("http"), (IUnknown **)&spAsynInnSocketListener.p, STRING_from_string("ssl/" + m_setsfile.get_string("globals", "version", "1.1")), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: http\n");
                return false;
            }
            spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocketListener, (void**)&m_spAsynTcpSocketListener[1]);

            HRESULT r0 = m_spAsynTcpSocketListener[1]->Set (DT_SetThreadpool, 0, threadpool); //设置接入线程池

            HRESULT r1 = m_spAsynTcpSocketListener[1]->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);
            HRESULT r2 = m_spAsynTcpSocketListener[1]->Bind(STRING_EX::null, sslport, FALSE, NULL); //同步bind
            if( r2 != 0 )
            {
                printf("bind *:%-4d[%s], error: %d\n", sslport, m_af == AF_INET? "ipv4" : "ipv6", r2);
                return false;
            }

            if(!sslport ) m_spAsynTcpSocketListener[1]->GetSockAddress(0, 0, &sslport, 0);
            printf("ssl.listen *:%-4d[%s]\n", sslport, m_af == AF_INET? "ipv4" : "ipv6");
        }

        for(int i = 0; i < 2; ++ i)
        {
            if(!m_spAsynTcpSocketListener[i] )
            {
                continue;
            }
            for(int c = 0; c < 2; ++ c)
            {
                CComPtr<IAsynIoOperation> spAsynIoOperation;
                m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, m_af, 0, IID_IAsynIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->SetOpParam1(i);
                m_spAsynTcpSocketListener[i]->Accept(spAsynIoOperation);
            }
        }
        return m_spAsynTcpSocketListener[0] || m_spAsynTcpSocketListener[1];
    }

    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;

        m_pWebsite->Shutdown();
    }

protected:
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;
    CComPtr<IAsynFileSystem > m_spAsynFileSystem;
    setting                   m_setsfile;
    std::unique_ptr<CWeb>     m_pWebsite;

    std::string m_cert_p12;
    std::string m_password;

    CComPtr<IAsynTcpSocketListener> m_spAsynTcpSocketListener[2];
    uint32_t m_af;

    std::map<std::string, std::string> m_mapMimes;
    struct userinfo
    {
        CComPtr<ISpeedController > spSpeedController;
        CComPtr<INet             > spDataTcpSocket;
        std::unique_ptr<CTranfile> tranfile;
        uint32_t starttime;
        std::string   skey;
    };

    std::map<std::string, userinfo > m_arId2Userinfos;       //skey->userinfo
    std::map<IAsynIoOperation *, userinfo *> m_arOp2Userinfos;
};

#endif//__SERVICE_H__
