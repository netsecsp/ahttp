#ifndef __WEB_H__
#define __WEB_H__
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
#include <frame/AsynFile_internal.h>
using namespace asynsdk;

class CWeb : public asyn_message_events_impl
{
public:
    CWeb(IAsynFrameThread *lpAsynFrameThread, const std::string &filepath)
        : m_filepath(filepath)
    {
        m_spAsynFrameThread = lpAsynFrameThread;
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CWeb)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );

public:
    bool Start(InstancesManager *lpInstancesManager, int watch)
    {
        if( m_filepath.empty()) return false;
        CreateDirectory(m_filepath.c_str(), NULL);
        if( watch == 0 ) return true; //不要监控目录
        if( watch == 1 ) CreateFilelist("/"); //自动创建索引目录

        if( lpInstancesManager->Require(STRING_from_string(IN_AsynFileSystem)) != S_OK )
        {
            printf("can't load plugin: %s\n", IN_AsynFileSystem);
            return false;
        }

        CComPtr<IAsynFileSystem> spAsynFileSystem;
        lpInstancesManager->GetInstance(STRING_from_string(IN_AsynFileSystem), IID_IAsynFileSystem, (IUnknown **)&spAsynFileSystem);

        HRESULT r1 = spAsynFileSystem->CreateAsynFileWatcher(m_spAsynFrameThread, STRING_from_string(m_filepath), TRUE, FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, &m_spAsynFileWatcher);
        if( r1 != S_OK )
        {
            printf("open %s, error: %d\n", m_filepath.c_str(), r1);
            return false;
        }

        CComPtr<IAsynIoOperation> spAsynIoOperation;
        m_spAsynFrame->CreateAsynIoOperation(0, 0, &spAsynIoOperation);

        printf("start to detect %s\n", m_filepath.c_str());
        m_spAsynFileWatcher->Commit(spAsynIoOperation, CP_ACP);
        return true;
    }
    bool CreateFilelist(const std::string &name, bool bCheckSubtree = true);
    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;

    CComPtr<IAsynFileWatcher> m_spAsynFileWatcher;
    std::string m_filepath;
};

#endif//__WEB_H__
