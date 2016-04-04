//
// Created by smorzhov on 17.03.16.
//
#pragma once

#include <node/node.h>
#include <node/node_object_wrap.h>
#include "RuleWrapper.h"
#include "../PreFirewallSrc/Rules/FloodlightFirewallRule.h"

namespace PreFirewall {
    class FloodlightFirewallRuleWrapper : public RuleWrapper {
    public:
        static void Init(v8::Isolate *);

        static void NewInstance(const v8::FunctionCallbackInfo<v8::Value> &);

        virtual void *GetRule() const { return rule; };

        virtual v8::Local<v8::Object> PackRule(v8::Isolate *, void *) const override;

        virtual void *UnpackRule(v8::Isolate *isolate, const v8::FunctionCallbackInfo<v8::Value> &args) const override;

    private:
        explicit FloodlightFirewallRuleWrapper(v8::Isolate *, const v8::FunctionCallbackInfo<v8::Value> &);

        ~FloodlightFirewallRuleWrapper();

        static void New(const v8::FunctionCallbackInfo<v8::Value> &args);

        static v8::Persistent<v8::Function> constructor;
    };
}