#ifndef __DOWNLOADER_H__
#define __DOWNLOADER_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 07/01/2016
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
#include <frame/AsynFile_internal.h>
#include <frame/AsynNetwork_internal.h>
#include <frame/asm/INet.h>
#include <frame/asm/IProxy.h>
#include "setting.h"
using namespace asynsdk;

class CDownloader : public asyn_message_events_impl
{
public:
    CDownloader(HANDLE hNotify, InstancesManager *lpInstanceManager, IAsynFrameThread *lpAsynFrameThread, uint32_t af = AF_INET)
	  : m_af(af), m_hNotify(hNotify), m_setsfile("config.txt")
    {
        m_spInstanceManager = lpInstanceManager;
        m_spAsynFrameThread = lpAsynFrameThread;
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork), IID_IAsynNetwork, (void **)&m_spAsynNetwork);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CDownloader)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IUnknown **objects );

public:
    bool Start(const std::string &url, uint64_t startpos)
    {
        //url格式， protocol://[user:password@]host[:port]/path/[;parameters][?query]#fragment
        std::string::size_type pos1 = url.find("://");
        if( pos1 == std::string::npos )
        {
            printf("fail to parse %s\n", url.c_str());
            return false;
        }
        std::string schema = url.substr(0, pos1);
        pos1 += 3/*skip "://" */;
        strlwr((char *)schema.c_str());
        if( schema != "http" && schema != "https" && schema != "ftp" && schema != "ftps" )
        {
            printf("invalid schema: %s\n", url.c_str());
            return false;
        }
 
        std::string::size_type pos2 = url.find('/', pos1);

        std::string hostport;
        if( pos2 == std::string::npos )
        {
            hostport = url.substr(pos1);
            m_filepath = "/";
        }
        else
        {
            hostport = url.substr(pos1, pos2 - pos1);

            std::string::size_type pos3 = url.find_first_of(";?#", pos2 + 1);
            m_filepath = pos3 == std::string::npos ? url.substr(pos2) : url.substr(pos2, pos3 - pos2);
            std::string::size_type pos4 = m_filepath.rfind('/');
            m_filename = m_filepath.substr(pos4 + 1);
        }

        if( m_filename.empty()) m_filename = "index.html";

        std::string::size_type pos3 = hostport.find('@');
        if( pos3 == std::string::npos )
        {
            pos3 = 0;
        }
        else
        {
            pos3 += 1;
        }
        std::string::size_type pos4 = hostport.find(':', pos3);
        if( pos4 == std::string::npos )
        {
            m_host = hostport.substr(pos3);
            m_port = 80;
            if( schema == "https") m_port = 443;
            if( schema == "ftp"  ) m_port = 21;
            if( schema == "ftps" ) m_port = 21; //显式over TLS
        }
        else
        {
            m_host = hostport.substr(pos3, pos4 - pos3);
            m_port = atoi(hostport.substr(pos4 + 1).c_str());
        }

        m_startpos = startpos;
        m_savename = m_setsfile.get_string("session", "filename", m_filename);

        std::string proxyname = m_setsfile.get_string("proxy", "protocol", "none");
        if( proxyname != "none" &&
            proxyname != "http" &&
            proxyname != "socks" )
        {
            printf("can't support %s-proxy\n", proxyname.c_str());
            return false;
        }

        CComPtr<IAsynTcpSocket> spAsynInnSocket;
        m_spAsynNetwork->CreateAsynTcpSocket(&spAsynInnSocket );

        CComPtr<IAsynRawSocket> spAsynPtlSocket;
        if( proxyname == "none" )
        {// 没有配置代理的情况: non
            m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("http"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(schema == "http" || schema == "ftp"? ("tcp/1.1") : (schema == "ftps"? "tls/1.1" : "ssl/1.1")/*tcp：表示http/ftp ssl：表示https/ftps*/), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: http\n");
                return false;
            }
        }
        else
        {// 已经配置代理的情况: http/socks proxy
            if( proxyname == "http" )
            {// http.proxy
                if( memcmp(schema.c_str(), "http", 4) == 0 )
                {
                    m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(   schema + "/" + m_setsfile.get_string("proxy", "version")), &spAsynPtlSocket );
                }
                else
                {
                    m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(proxyname + "/" + m_setsfile.get_string("proxy", "version")), &spAsynPtlSocket );
                }
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", proxyname.c_str());
                    return false;
                }

                m_filepath = url;

                CComPtr<IAsynProxySocket> spProxy;
                spAsynPtlSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                HRESULT hr = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), schema!="https"? m_setsfile.get_long("proxy", "port", 8080) : m_setsfile.get_long("proxy", "port_2", 8443), STRING_EX::null, &params);
            }
            else
            {// socks.proxy
                if( memcmp(schema.c_str(), "http", 4) != 0 )
                {
                    printf("invalid schema: %s\n", url.c_str());
                    return false;
                }

                CComPtr<IAsynRawSocket> spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(proxyname + "/" + m_setsfile.get_string("proxy", "version")), &spAsynTmpSocket );
                if( spAsynTmpSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", proxyname.c_str());
                    return false;
                }

                CComPtr<IAsynProxySocket> spProxy;
                spAsynTmpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                HRESULT hr = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), m_setsfile.get_long("proxy", "port", 1080), STRING_EX::null, &params);

                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("http"), (IUnknown **)&spAsynTmpSocket.p, STRING_from_string(schema=="http"? "tcp/1.1" : "ssl/1.1"), &spAsynPtlSocket );
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: http\n");
                    return false;
                }
            }
        }

        spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocket, (void **)&m_spAsynTcpSocket);

        //设置接收数据速度: B/s
        m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (void **)&m_spSpeedController);
        m_spSpeedController->SetMaxSpeed(m_setsfile.get_long("session", "max_recvspeed", -1));
        bool ret = asynsdk::SetSpeedController(m_spAsynTcpSocket, Io_recv, -1, m_spSpeedController);

        m_spAsynTcpSocket->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);

        //开始连接...
        CComPtr<IAsynNetIoOperation> spAsynIoOperation;
        m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, m_af, 0, IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);

        if( proxyname == "none" )
            printf("start to connect %s:%d\n", m_host.c_str(), m_port);
        else
            printf("start to connect %s:%d via %s-proxyserver[%s:%d]\n", m_host.c_str(), m_port, proxyname.c_str(), m_setsfile.get_string("proxy", "host", "127.0.0.1").c_str(), m_setsfile.get_long("proxy", "port", 1080));
        m_spAsynTcpSocket->Connect(STRING_from_string(m_host), m_port, 0, spAsynIoOperation, m_setsfile.get_long("session", "connect_timeout", 2000/*2sec*/));
        return true;
    }

    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;
    HANDLE   m_hNotify;

    CComPtr<ISpeedController> m_spSpeedController;
    uint32_t m_starttime;
    uint32_t m_af;

    CComPtr<IAsynIoBridge   > m_spAsynIoBridge;
    CComPtr<IAsynTcpSocket  > m_spAsynTcpSocket;

    std::string   m_host;
    PORT          m_port;

    setting       m_setsfile;
    std::string   m_filename;
    std::string   m_filepath;
    std::string   m_savename;
    uint64_t      m_datasize; //尚未接收数据的长度
    uint64_t 	  m_startpos; //从０开始
};

#endif//__DOWNLOADER_H__
