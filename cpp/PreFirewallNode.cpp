//
// Created by smorzhov on 13.03.16.
//
#include <node/node.h>
#include "AnomaliesResolverWrapper/AnomaliesResolverWrapper.h"
#include "RuleWrappers/FloodlightACLRuleWrapper.h"
#include "RuleWrappers/FloodlightFirewallRuleWrapper.h"

namespace PreFirewall {

    using v8::FunctionCallbackInfo;
    using v8::Isolate;
    using v8::Local;
    using v8::Number;
    using v8::Object;
    using v8::String;
    using v8::Value;

    void CreateAnomaliesResolver(const FunctionCallbackInfo<Value>& args) {
        AnomaliesResolverWrapper::NewInstance(args);
    }

    void CreateFloodlightACLRule(const FunctionCallbackInfo<Value>& args) {
        FloodlightACLRuleWrapper::NewInstance(args);
    }

    void CreateFloodlightFirewallRule(const FunctionCallbackInfo<Value>& args) {
        FloodlightFirewallRuleWrapper::NewInstance(args);
    }

    void Method(const FunctionCallbackInfo <Value> &args) {
        Isolate *isolate = args.GetIsolate();
        args.GetReturnValue().Set(String::NewFromUtf8(isolate, "Hello world!"));
    }

    void InitAll(Local <Object> exports) {
        AnomaliesResolverWrapper::Init(exports->GetIsolate());
        FloodlightACLRuleWrapper::Init(exports->GetIsolate());
        FloodlightFirewallRuleWrapper::Init(exports->GetIsolate());

        NODE_SET_METHOD(exports, "createAnomaliesResolver", CreateAnomaliesResolver);
        NODE_SET_METHOD(exports, "createFloodlightACLRule", CreateFloodlightACLRule);
        NODE_SET_METHOD(exports, "createFloodlightFirewallRule", CreateFloodlightFirewallRule);
        NODE_SET_METHOD(exports, "helloWorld", Method);
    }

    NODE_MODULE(PreFirewall, InitAll)
}