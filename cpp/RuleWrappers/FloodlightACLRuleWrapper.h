//
// Created by smorzhov on 17.03.16.
//
#pragma once

#include <node/node.h>
#include <node/node_object_wrap.h>
#include <string>
#include "../PreFirewallSrc/Rules/FloodlightACLRule.h"
#include "RuleWrapper.h"

namespace PreFirewall {

    class FloodlightACLRuleWrapper : public virtual RuleWrapper {
    public:
        static void Init(v8::Isolate *);

        static void NewInstance(const v8::FunctionCallbackInfo<v8::Value> &);

        virtual void *GetRule() const { return rule; };

        virtual v8::Local<v8::Object> PackRule(v8::Isolate *, void *) const override;

        virtual void *UnpackRule(v8::Isolate *isolate, const v8::FunctionCallbackInfo<v8::Value> &args) const override;

    private:
        explicit FloodlightACLRuleWrapper(v8::Isolate *, const v8::FunctionCallbackInfo<v8::Value> &);

        ~FloodlightACLRuleWrapper();

        static void New(const v8::FunctionCallbackInfo<v8::Value> &args);

        static v8::Persistent<v8::Function> constructor;
    };
}