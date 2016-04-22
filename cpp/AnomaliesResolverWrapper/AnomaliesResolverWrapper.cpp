//
// Created by smorzhov on 25.03.16.
//

#include "AnomaliesResolverWrapper.h"
#include "../RuleWrappers/RuleWrapper.h"
#include "../RuleWrappers/FloodlightACLRuleWrapper.h"
#include <node/node.h>
#include <node/v8.h>

namespace PreFirewall {

    using v8::Function;
    using v8::FunctionCallbackInfo;
    using v8::FunctionTemplate;
    using v8::Isolate;
    using v8::Local;
    using v8::Object;
    using v8::Persistent;
    using v8::String;
    using v8::Value;
    using v8::Array;
    using v8::Handle;
    using v8::External;
    using std::vector;
    using v8::Exception;

    v8::Persistent<Function> AnomaliesResolverWrapper::constructor;

    AnomaliesResolverWrapper::AnomaliesResolverWrapper() {
        anomaliesResolver = new AnomaliesResolver();
    }

    AnomaliesResolverWrapper::~AnomaliesResolverWrapper() {
        //delete anomaliesResolver;
    }

    void AnomaliesResolverWrapper::Init(Isolate* isolate) {
        // Prepare constructor template
        Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
        tpl->SetClassName(String::NewFromUtf8(isolate, "AnomaliesResolver"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        NODE_SET_PROTOTYPE_METHOD(tpl, "findAnomalies", FindAnomalies);
        NODE_SET_PROTOTYPE_METHOD(tpl, "undoChanges", UndoChanges);
        NODE_SET_PROTOTYPE_METHOD(tpl, "getRules", GetRules);
        NODE_SET_PROTOTYPE_METHOD(tpl, "removeRule", RemoveRule);

        constructor.Reset(isolate, tpl->GetFunction());
    }

    void AnomaliesResolverWrapper::New(const FunctionCallbackInfo<Value>& args) {
        Isolate* isolate = args.GetIsolate();

        if (args.IsConstructCall()) {
            // Invoked as constructor: `new MyObject(...)`
            AnomaliesResolverWrapper *anomaliesResolverWrapper = new AnomaliesResolverWrapper();
            anomaliesResolverWrapper->Wrap(args.This());
            args.GetReturnValue().Set(args.This());
        } else {
            // Invoked as plain function `MyObject(...)`, turn into construct call.
            Local<Function> cons = Local<Function>::New(isolate, constructor);
            args.GetReturnValue().Set(cons->NewInstance());
        }
    }

    void AnomaliesResolverWrapper::NewInstance(const FunctionCallbackInfo<Value>& args) {
        Isolate* isolate = args.GetIsolate();

        Local<Function> cons = Local<Function>::New(isolate, constructor);
        Local<Object> instance = cons->NewInstance();

        args.GetReturnValue().Set(instance);
    }

    void AnomaliesResolverWrapper::FindAnomalies(const FunctionCallbackInfo<Value> &args) {
        Isolate* isolate = args.GetIsolate();

        AnomaliesResolverWrapper *anomaliesResolverWrapper = ObjectWrap::Unwrap<AnomaliesResolverWrapper>(args.Holder());
        if (args[0]->IsUndefined()) {
            isolate->ThrowException(Exception::TypeError(
                    String::NewFromUtf8(isolate, "Wrong arguments")));
            return;
        }
        RuleWrapper* rule = ObjectWrap::Unwrap<RuleWrapper>(args[0]->ToObject());

        vector<void *> conflictedRules = anomaliesResolverWrapper->anomaliesResolver->findAnomalies(rule->GetRule());
        Local<Array> resultList = Array::New(isolate);
        for (unsigned int i = 0; i < conflictedRules.size(); ++i) {
            Local<Object> r = Object::New(isolate);
            rule->PackRule(isolate, r, conflictedRules[i]);
            resultList->Set(i, r);
        }
        args.GetReturnValue().Set(resultList);
    }

    void AnomaliesResolverWrapper::UndoChanges(const FunctionCallbackInfo<Value> &args) {
        AnomaliesResolverWrapper *anomaliesResolverWrapper = ObjectWrap::Unwrap<AnomaliesResolverWrapper>(args.Holder());
        anomaliesResolverWrapper->anomaliesResolver->undoChanges();
    }

    void AnomaliesResolverWrapper::GetRules(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        AnomaliesResolverWrapper *anomaliesResolverWrapper = ObjectWrap::Unwrap<AnomaliesResolverWrapper>(args.Holder());
        if (args[0]->IsUndefined()) {
            isolate->ThrowException(Exception::TypeError(
                    String::NewFromUtf8(isolate, "Wrong arguments")));
            return;
        }
        RuleWrapper* rule = ObjectWrap::Unwrap<RuleWrapper>(args[0]->ToObject());
        vector<void *> rules = anomaliesResolverWrapper->anomaliesResolver->getNewRules();
        Local<Array> resultList = Array::New(isolate);
        for (unsigned int i = 0; i < rules.size(); ++i) {
            Local<Object> r = Object::New(isolate);
            rule->PackRule(isolate, r, rules[i]);
            resultList->Set(i, r);
        }
        args.GetReturnValue().Set(resultList);
    }

    void AnomaliesResolverWrapper::RemoveRule(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        AnomaliesResolverWrapper *anomaliesResolverWrapper = ObjectWrap::Unwrap<AnomaliesResolverWrapper>(args.Holder());
        if (args[0]->IsUndefined()) {
            isolate->ThrowException(Exception::TypeError(
                    String::NewFromUtf8(isolate, "Wrong arguments")));
            return;
        }
        int id = args[0]->Int32Value();
        bool res = anomaliesResolverWrapper->anomaliesResolver->remove(id);
        if (!res) {
            isolate->ThrowException(Exception::TypeError(
                    String::NewFromUtf8(isolate, "The rule was not removed!")));
            return;
        }
        args.GetReturnValue().Set(res);

    }
}  // namespace PreFirewall
