//
// Created by smorzhov on 17.03.16.
//
#pragma once

#include <node/node.h>
#include <node/node_object_wrap.h>
#include <string>
#include "../PreFirewallSrc/Rules/FloodlightACLRule.h"
#include "RuleWrapper.h"
#include "../PreFirewallSrc/Algorithm/AnomaliesResolver.h"

namespace PreFirewall {

    class FloodlightACLRuleWrapper : public RuleWrapper {
    public:
        static void Init(v8::Isolate *);

        static void NewInstance(const v8::FunctionCallbackInfo<v8::Value> &);

        virtual void *GetRule() const { return rule; };

        virtual void PackRule(v8::Isolate *, v8::Local<v8::Object>&, AnomaliesResolver::Conflict *) const override;

        static void *UnpackRule(v8::Isolate *isolate, const v8::FunctionCallbackInfo<v8::Value> &args);

    private:
        explicit FloodlightACLRuleWrapper(FloodlightACLRule* rule = nullptr);

        ~FloodlightACLRuleWrapper();

        static short GetNwProto(v8::Handle<v8::Value>&);

        static void New(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void ToString(const v8::FunctionCallbackInfo<v8::Value>& args);

        static void GetId(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void SetId(const v8::FunctionCallbackInfo<v8::Value> &args);

        static v8::Persistent<v8::Function> constructor;
    };
}