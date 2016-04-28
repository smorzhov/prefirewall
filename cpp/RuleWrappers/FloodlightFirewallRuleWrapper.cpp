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
    using v8::Number;
    using v8::Value;
    using v8::Handle;
    using v8::Exception;

    v8::Persistent<Function> FloodlightFirewallRuleWrapper::constructor;

    FloodlightFirewallRuleWrapper::FloodlightFirewallRuleWrapper(FloodlightFirewallRule *rule) {
        this->rule = rule;
    }

    FloodlightFirewallRuleWrapper::~FloodlightFirewallRuleWrapper() {
        //delete rule;
    }

    void FloodlightFirewallRuleWrapper::Init(Isolate *isolate) {
        // Prepare constructor template
        Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
        tpl->SetClassName(String::NewFromUtf8(isolate, "FloodlightFirewallRule"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        NODE_SET_PROTOTYPE_METHOD(tpl, "toString", ToString);
        NODE_SET_PROTOTYPE_METHOD(tpl, "getId", GetId);
        NODE_SET_PROTOTYPE_METHOD(tpl, "setId", SetId);

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
            FloodlightFirewallRuleWrapper *ruleWrapper =
                    new FloodlightFirewallRuleWrapper((FloodlightFirewallRule *)UnpackRule(isolate, args));
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

    void FloodlightFirewallRuleWrapper::PackRule(Isolate *isolate, Local<Object>& obj,
                                                 AnomaliesResolver::Conflict *rule) const {
        FloodlightFirewallRule *r = static_cast<FloodlightFirewallRule *>(rule->rule);
        obj->Set(String::NewFromUtf8(isolate, "type"), v8::Int32::New(isolate, (int32_t)rule->type));
        obj->Set(String::NewFromUtf8(isolate, "rule-id"), v8::Int32::New(isolate, r->getId()));
        obj->Set(String::NewFromUtf8(isolate, "switchid"), v8::String::NewFromUtf8(isolate, r->getSwitchId().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "src-inport"), v8::Int32::New(isolate, (int) r->getSrcInport()));
        obj->Set(String::NewFromUtf8(isolate, "src-mac"), v8::String::NewFromUtf8(isolate, r->getSrcMac().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dst-mac"), v8::String::NewFromUtf8(isolate, r->getDstMac().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dl-type"), v8::Int32::New(isolate, (int) r->getDlType()));
        obj->Set(String::NewFromUtf8(isolate, "src-ip"),
                 v8::String::NewFromUtf8(isolate, r->getSrcIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dst-ip"),
                 v8::String::NewFromUtf8(isolate, r->getDstIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "nw-proto"), v8::Int32::New(isolate, (int) r->getNwProto()));
        obj->Set(String::NewFromUtf8(isolate, "tp-src"), v8::Int32::New(isolate, (int) r->getTpSrc()));
        obj->Set(String::NewFromUtf8(isolate, "tp-dst"), v8::Int32::New(isolate, (int) r->getTpDst()));
        obj->Set(String::NewFromUtf8(isolate, "priority"), v8::Int32::New(isolate, (int) r->getPriority()));
        if (r->getAction() == Rule::Action::ALLOW)
            obj->Set(String::NewFromUtf8(isolate, "action"), v8::String::NewFromUtf8(isolate, "allow"));
        else obj->Set(String::NewFromUtf8(isolate, "action"), v8::String::NewFromUtf8(isolate, "deny"));
    }

    void *FloodlightFirewallRuleWrapper::UnpackRule(Isolate *isolate, const FunctionCallbackInfo<Value> &args) {
        Handle<Object> ruleObj = Handle<Object>::Cast(args[0]);
        Handle<Value> id = ruleObj->Get(String::NewFromUtf8(isolate, "rule-id"));
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
        short proto = GetNwProto(nwProto);
        short dl = GetDlType(dlType);
        Rule *rule = new FloodlightFirewallRule(
                std::string(*(String::Utf8Value(switchId->ToString()))),
                (short) srcInport->NumberValue(),
                std::string(*(String::Utf8Value(srcMac->ToString()))),
                std::string(*(String::Utf8Value(dstMac->ToString()))),
                dl,
                std::string(*(String::Utf8Value(srcIp->ToString()))),
                std::string(*(String::Utf8Value(dstIp->ToString()))),
                proto,
                (short) tpSrc->NumberValue(),
                (short) tpDst->NumberValue(),
                (uint32_t) priority->NumberValue(),
                std::string(*(String::Utf8Value(action->ToString())))
        );
        rule->setId(id->NumberValue());
        return rule;
    }

    short FloodlightFirewallRuleWrapper::GetNwProto(v8::Handle<v8::Value> &nwProto) {
        if (nwProto->IsNumber()) return (short)nwProto->Int32Value();
        string proto = *(String::Utf8Value(nwProto->ToString()));
        if (proto == "tcp" || proto == "TCP") return (short)6;
        if (proto == "udp" || proto == "UDP") return (short)17;
        if (proto == "icmp" || proto == "ICMP") return (short)1;
        return 0;
    }

    short FloodlightFirewallRuleWrapper::GetDlType(v8::Handle<v8::Value> &dlType) {
        if (dlType->IsNumber()) return (short)dlType->Int32Value();
        string dl = *(String::Utf8Value(dlType->ToString()));
        if (dl == "arp" || dl == "ARP") return (short)2054;
        if (dl == "ipv4" || dl == "IPV4" || dl == "IPv4") return (short)2048;
        return 0;
    }

    void FloodlightFirewallRuleWrapper::ToString(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        FloodlightFirewallRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightFirewallRuleWrapper>(args.Holder());
        args.GetReturnValue().Set(String::NewFromUtf8(isolate, obj->rule->toString().c_str()));
    }

    void FloodlightFirewallRuleWrapper::GetId(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        FloodlightFirewallRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightFirewallRuleWrapper>(args.Holder());
        args.GetReturnValue().Set(Number::New(isolate, obj->rule->getId()));
    }

    void FloodlightFirewallRuleWrapper::SetId(const v8::FunctionCallbackInfo<v8::Value> &args) {
        //Isolate* isolate = args.GetIsolate();
        FloodlightFirewallRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightFirewallRuleWrapper>(args.Holder());
        int32_t id = args[0]->IsUndefined() ? 0 : args[0]->Int32Value();
        if (id != 0)
            obj->rule->setId(id);
        //todo else...
    }
}