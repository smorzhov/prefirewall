//
// Created by smorzhov on 17.03.16.
//

#pragma once

#include "../PreFirewallSrc/Rules/Rule.h"

class RuleWrapper : public node::ObjectWrap {
public:
    virtual void *GetRule() const = 0;

    virtual void PackRule(v8::Isolate *, v8::Local<v8::Object> &, void *) const = 0;

    //virtual void *UnpackRule(v8::Isolate *, const v8::FunctionCallbackInfo<v8::Value> &args) const = 0;

protected:
    virtual ~RuleWrapper() { }

    Rule *rule;
};
