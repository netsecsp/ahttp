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
#include "Downloader.h"
#include <frame/asm/ISsl.h>

BEGIN_ASYN_MESSAGE_MAP(CDownloader)
	ON_IOMSG_NOTIFY(OnIomsgNotify)
	ON_EVENT_NOTIFY(OnEventNotify, IAsynIoOperation)
	ON_QUERY_RESULT(OnQueryResult, IUnknown)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CDownloader::OnQueryResult( uint64_t lParam1, uint64_t lParam2, IUnknown **objects )
{
    if( lParam1 == 0 )
    {
        asynsdk::CStringSetter d(1);
        asynsdk::CMemorySetter c((void*)0);
        ((IKeyvalSetter*)objects[0])->Get(STRING_from_string(";dattype"), 0, 0, &d);
        ((IKeyvalSetter*)objects[0])->Get(STRING_from_string(";context"), 0, 0, &c);
        if( d.m_val.rfind("cert.verify") != std::string::npos )
        {// cert.verify
            ISsl *pSsl = (ISsl*)lParam2;
            return pSsl->VerifyPeerCertificate(*(handle*)c.m_val.ptr, 0x1000);
        }
        return E_NOTIMPL;
    }

    if( m_spAsynIoBridge != (IAsynIoBridge *)lParam1) return E_NOTIMPL;

    uint32_t bCompleted;
    ((IAsynIoOperation*)objects[0])->GetCompletedResult(0, 0, &bCompleted);

    if( m_datasize != _UI64_MAX ) m_datasize -= lParam2;
    if( m_datasize != _UI64_MAX )
        printf("transmit: %I64d/%I64d/%d\n", lParam2, m_datasize, bCompleted);
    else
        printf("transmit: %I64d/%d\n", lParam2, bCompleted);

    if( bCompleted ) m_datasize = 0; //mark download complete

    return m_datasize != 0 ? S_OK : S_FALSE;
}

HRESULT CDownloader::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR, lTransferedBytes;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, &lTransferedBytes, 0);

    switch(lAction)
    {
    case Io_connect:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("connect, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }
        else
        {
            std::string host; asynsdk::CStringSetterRef temp(1, &host);
            PORT		port;
            {// 打印链接信息
                CComPtr<IAsynNetIoOperation> spAsynIoOperation;
                lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->GetPeerAddress(&temp, 0, &port, &m_af);
                printf("connected %s:%d[%s]\n", host.c_str(), port, m_af == AF_INET ? "ipv4" : "ipv6");
            }

            asynsdk::CKeyvalSetter params(1);
          //params.Set(STRING_from_string("User-Agent"), 1, STRING_from_string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"));
            params.Set(STRING_from_string("Accept"    ), 1, STRING_from_string("*/*"));

            const std::string &szreferurl = m_setsfile.get_string("session",  "referurl");
            if( szreferurl.empty() == false ) params.Set(STRING_from_string("Referer"), 1, STRING_from_string(szreferurl));

            if( m_startpos != 0 )
            {
                char temp[64]; sprintf(temp, "bytes=%I64d-", m_startpos);
                params.Set(STRING_from_string("Range"     ), 1, STRING_from_string(temp));
            }

            CComPtr<INet> spINet; m_spAsynTcpSocket->QueryInterface(IID_INet, (void **)&spINet);
            return spINet->SendPacket(STRING_from_string("GET"), STRING_from_string(m_filepath), &params, lpAsynIoOperation);
        }
    }

    case Io_recv:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("recv, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }
        else
        {// 成功收到 http 响应
            CComPtr<INetmsg> spRspmsg;
            lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (void **)&spRspmsg);
            if( spRspmsg == NULL )
            {
                printf("recv, not found http ack\n");
                SetEvent(m_hNotify);
                break;
            }

            STRING Status;
            STRING Params;
            spRspmsg->Getline(&Status, &Params, 0);
            std::string status = string_from_STRING(Status);
            std::string params = string_from_STRING(Params);
            lErrorCode = atoi(status.c_str());
            if( lErrorCode / 100 != 2 )
            {
                printf("%d %s\n", lErrorCode, params.c_str());
                SetEvent(m_hNotify);
                break;
            }

            if( lErrorCode != 206 ) m_datasize = 0;

            asynsdk::CStringSetter v(1);
            if( spRspmsg->Get(STRING_from_string("Transfer-Encoding"), 0, 0, v.Clear()) == S_OK )
            {
                printf("chunked\n");
                m_datasize = _UI64_MAX;
            }
            else
            {
                if( spRspmsg->Get(STRING_from_string("Content-Length"), 0, 0, v.Clear()) == S_OK )
                {
                    printf("datasize: %s\n", v.m_val.c_str());
                    m_datasize = _atoi64(v.m_val.c_str());
                }
                else
                {
                    printf("datasize: unkown\n");
                    m_datasize = _UI64_MAX;
                }
            }

            if( m_datasize == 0 )   //filesize is zero
            {
                printf("%s is zero\n", m_filename.c_str());
                SetEvent(m_hNotify);
                break;
            }

            m_spInstanceManager->Verify(STRING_from_string(IN_AsynFileSystem));
            CComPtr<IAsynFileSystem> spAsynFileSystem;
            HRESULT r1 = m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynFileSystem), IID_IAsynFileSystem, (void **)&spAsynFileSystem);
            if( r1 != S_OK )
            {
                printf("can't load plugin: %s\n", IN_AsynFileSystem);
                SetEvent(m_hNotify);
                break;
            }

            CComPtr<IAsynFile> spAsynFile;
            spAsynFileSystem->CreateAsynFile(&spAsynFile);
            HRESULT r2 = spAsynFile->Open( m_spAsynFrameThread,
                                           STRING_from_string(m_savename), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL );
            if( r2 != S_OK )
            {
                printf("open %s, error: %d\n", m_savename.c_str(), r2);
                SetEvent(m_hNotify);
                break;
            }

            m_spAsynFrameThread->CreateAsynIoBridge( m_spAsynTcpSocket, spAsynFile, 0, &m_spAsynIoBridge );
            if( m_startpos )
            {
                CComPtr<IAsynFileIoOperation> spAsynIoOperation; m_spAsynIoBridge->Get(BT_GetTargetIoOperation, 0, IID_IAsynFileIoOperation, (void **)&spAsynIoOperation);
                spAsynIoOperation->SetPosition(m_startpos); //设置开始写入数据时文件的偏移
            }

            m_spAsynIoBridge->Invoke(0, GetAsynMessageEvents());
            m_starttime = ::GetTickCount(); //开始计时
            break;
        }
    }

    case Io_send:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("send, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            break;
        }
        else
        {// 发送请求成功，准备接收http响应报文的头部数据
            lpAsynIoOperation->SetIoParam1(0); //表示只接收http头部
            return m_spAsynTcpSocket->Read(lpAsynIoOperation);
        }
    }
    }
    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}

HRESULT CDownloader::OnEventNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation )
{
    if( m_spAsynIoBridge != (IAsynIoBridge *)lParam1) return S_OK;

    if( lParam2 == NO_ERROR ||
        lParam2 == AE_RESET && m_datasize == _UI64_MAX ) //没有文件大小的情况
    {
        uint32_t speed;
        m_spSpeedController->GetPostIoBytes(0, &speed);
        printf("%s is saved, speed: %.2fKB/s, cost: %dms\n", m_savename.c_str(), speed / 1024.0, ::GetTickCount() - m_starttime);
    }
    else
    {
        CComPtr<IAsynFileIoOperation> spAsynIoOperation;
		m_spAsynIoBridge->Get(BT_GetTargetIoOperation, 0, IID_IAsynFileIoOperation, (void **)&spAsynIoOperation);
        spAsynIoOperation->GetPosition(&m_startpos );
        lpAsynIoOperation->GetOpParams( 0, 0, &lParam1 );
        if( lParam1 == Io_recv )
            printf("download %s on position: %I64d, error: %I64d\n", m_savename.c_str(), m_startpos, lParam2);
        else
            printf("save %s on position: %I64d, error: %I64d\n", m_savename.c_str(), m_startpos, lParam2);
    }

    m_spAsynIoBridge->Close(0); //close sock/file
    SetEvent(m_hNotify);
    return S_OK;
}
