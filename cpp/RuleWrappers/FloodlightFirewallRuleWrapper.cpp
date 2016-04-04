//
// Created by smorzhov on 17.03.16.
//

#include "FloodlightFirewallRuleWrapper.h"

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
    using v8::Handle;
    using v8::Exception;

    v8::Persistent<Function> FloodlightFirewallRuleWrapper::constructor;

    FloodlightFirewallRuleWrapper::FloodlightFirewallRuleWrapper(Isolate *isolate,
                                                                 const FunctionCallbackInfo<Value> &args) {

    }

    FloodlightFirewallRuleWrapper::~FloodlightFirewallRuleWrapper() {
    }

    void FloodlightFirewallRuleWrapper::Init(Isolate *isolate) {
        // Prepare constructor template
        Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
        tpl->SetClassName(String::NewFromUtf8(isolate, "FloodlightFirewallRule"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        constructor.Reset(isolate, tpl->GetFunction());
    }

    void FloodlightFirewallRuleWrapper::New(const FunctionCallbackInfo<Value> &args) {
        Isolate *isolate = args.GetIsolate();
        if (args.IsConstructCall()) {
            // Invoked as constructor: `new MyObject(...)`
            if (args[0]->IsUndefined()) {
                isolate->ThrowException(Exception::TypeError(
                        String::NewFromUtf8(isolate, "Wrong arguments")));
                return;
            }
            FloodlightFirewallRuleWrapper *ruleWrapper = new FloodlightFirewallRuleWrapper(isolate, args);
            ruleWrapper->Wrap(args.This());
            args.GetReturnValue().Set(args.This());
        } else {
            // Invoked as plain function `MyObject(...)`, turn into construct call.
            const int argc = 1;
            Local<Value> argv[argc] = {args[0]};
            Local<Function> cons = Local<Function>::New(isolate, constructor);
            args.GetReturnValue().Set(cons->NewInstance(argc, argv));
        }
    }

    void FloodlightFirewallRuleWrapper::NewInstance(const FunctionCallbackInfo<Value> &args) {
        Isolate *isolate = args.GetIsolate();

        const unsigned argc = 1;
        Local<Value> argv[argc] = {args[0]};
        Local<Function> cons = Local<Function>::New(isolate, constructor);
        Local<Object> instance = cons->NewInstance(argc, argv);

        args.GetReturnValue().Set(instance);
    }

    Local<Object> FloodlightFirewallRuleWrapper::PackRule(Isolate *isolate, void *rule) const {
        Local<Object> obj = Object::New(isolate);
        FloodlightFirewallRule *r = static_cast<FloodlightFirewallRule *>(rule);
        obj->Set(String::NewFromUtf8(isolate, "switchId"), v8::String::NewFromUtf8(isolate, r->getSwitchId().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "srcInport"), v8::Int32::New(isolate, (int) r->getSrcInport()));
        obj->Set(String::NewFromUtf8(isolate, "srcMac"), v8::String::NewFromUtf8(isolate, r->getSrcMac().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dstMac"), v8::String::NewFromUtf8(isolate, r->getDstMac().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dlType"), v8::Int32::New(isolate, (int) r->getDlType()));
        obj->Set(String::NewFromUtf8(isolate, "srcIp"),
                 v8::String::NewFromUtf8(isolate, r->getSrcIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dstIp"),
                 v8::String::NewFromUtf8(isolate, r->getDstIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "nwProto"), v8::Int32::New(isolate, (int) r->getNwProto()));
        obj->Set(String::NewFromUtf8(isolate, "tpSrc"), v8::Int32::New(isolate, (int) r->getTpSrc()));
        obj->Set(String::NewFromUtf8(isolate, "tpDst"), v8::Int32::New(isolate, (int) r->getTpDst()));
        obj->Set(String::NewFromUtf8(isolate, "priority"), v8::Int32::New(isolate, (int) r->getPriority()));
        if (r->getAction() == Rule::Action::ALLOW)
            obj->Set(String::NewFromUtf8(isolate, "dstIp"), v8::String::NewFromUtf8(isolate, "allow"));
        else obj->Set(String::NewFromUtf8(isolate, "dstIp"), v8::String::NewFromUtf8(isolate, "deny"));
        return obj;
    }

    void *FloodlightFirewallRuleWrapper::UnpackRule(Isolate *isolate, const FunctionCallbackInfo<Value> &args) const {
        Handle<Object> ruleObj = Handle<Object>::Cast(args[0]);
        Handle<Value> switchId = ruleObj->Get(String::NewFromUtf8(isolate, "switchid"));
        Handle<Value> srcInport = ruleObj->Get(String::NewFromUtf8(isolate, "src-inport"));
        Handle<Value> srcMac = ruleObj->Get(String::NewFromUtf8(isolate, "src-mac"));
        Handle<Value> dstMac = ruleObj->Get(String::NewFromUtf8(isolate, "dst-mac"));
        Handle<Value> dlType = ruleObj->Get(String::NewFromUtf8(isolate, "dl-type"));
        Handle<Value> srcIp = ruleObj->Get(String::NewFromUtf8(isolate, "src-ip"));
        Handle<Value> dstIp = ruleObj->Get(String::NewFromUtf8(isolate, "dst-ip"));
        Handle<Value> nwProto = ruleObj->Get(String::NewFromUtf8(isolate, "nw-proto"));
        Handle<Value> tpSrc = ruleObj->Get(String::NewFromUtf8(isolate, "tp-src"));
        Handle<Value> tpDst = ruleObj->Get(String::NewFromUtf8(isolate, "tp-dst"));
        Handle<Value> priority = ruleObj->Get(String::NewFromUtf8(isolate, "priority"));
        Handle<Value> action = ruleObj->Get(String::NewFromUtf8(isolate, "action"));
        String::Utf8Value(srcIp->ToString());
        Rule *rule = new FloodlightFirewallRule(
                std::string(*(String::Utf8Value(switchId->ToString()))),
                (short) srcInport->NumberValue(),
                std::string(*(String::Utf8Value(srcMac->ToString()))),
                std::string(*(String::Utf8Value(dstMac->ToString()))),
                (short) dlType->NumberValue(),
                std::string(*(String::Utf8Value(srcIp->ToString()))),
                std::string(*(String::Utf8Value(dstIp->ToString()))),
                (short) nwProto->NumberValue(),
                (short) tpSrc->NumberValue(),
                (short) tpDst->NumberValue(),
                (uint32_t) priority->NumberValue(),
                std::string(*(String::Utf8Value(action->ToString())))
        );
        return rule;
    }


}