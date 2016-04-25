//
// Created by smorzhov on 25.03.16.
//

#pragma once

#include <node/node.h>
#include <node/node_object_wrap.h>
#include "../PreFirewallSrc/Algorithm/AnomaliesResolver.h"
#include "../RuleWrappers/RuleWrapper.h"

namespace PreFirewall {

    class AnomaliesResolverWrapper : public node::ObjectWrap {
    public:
        static void Init(v8::Isolate *isolate);

        static void NewInstance(const v8::FunctionCallbackInfo<v8::Value> &args);

    private:
        explicit AnomaliesResolverWrapper();

        ~AnomaliesResolverWrapper();

        static void New(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void FindAnomalies(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void UndoChanges(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void GetRules(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void RemoveRuleById(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void RemoveRuleByValue(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void FindAnomaliesAsync(const v8::FunctionCallbackInfo<v8::Value> &args);

        static void UndoChangesAsync(const v8::FunctionCallbackInfo<v8::Value> &args);

        static v8::Persistent<v8::Function> constructor;

        AnomaliesResolver *anomaliesResolver;
    };
}  // namespace PreFirewall