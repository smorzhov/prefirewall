//
// Created by smorzhov on 17.03.16.
//

#include "FloodlightACLRuleWrapper.h"

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

    v8::Persistent<Function> FloodlightACLRuleWrapper::constructor;

    FloodlightACLRuleWrapper::FloodlightACLRuleWrapper(FloodlightACLRule *rule) {
        this->rule = rule;
    }

    FloodlightACLRuleWrapper::~FloodlightACLRuleWrapper() {
        //delete rule;
    }

    void FloodlightACLRuleWrapper::Init(Isolate *isolate) {
        // Prepare constructor template
        Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
        tpl->SetClassName(String::NewFromUtf8(isolate, "FloodlightACLRule"));
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

        NODE_SET_PROTOTYPE_METHOD(tpl, "toString", ToString);
        NODE_SET_PROTOTYPE_METHOD(tpl, "getId", GetId);
        NODE_SET_PROTOTYPE_METHOD(tpl, "setId", SetId);

        constructor.Reset(isolate, tpl->GetFunction());
    }

    void FloodlightACLRuleWrapper::New(const FunctionCallbackInfo<Value> &args) {
        Isolate *isolate = args.GetIsolate();
        if (args.IsConstructCall()) {
            // Invoked as constructor: `new MyObject(...)`
            if (args[0]->IsUndefined()) {
                isolate->ThrowException(Exception::TypeError(
                        String::NewFromUtf8(isolate, "Wrong arguments")));
                return;
            }
            FloodlightACLRuleWrapper *ruleWrapper =
                    new FloodlightACLRuleWrapper((FloodlightACLRule *)UnpackRule(isolate, args));
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

    void FloodlightACLRuleWrapper::NewInstance(const FunctionCallbackInfo<Value> &args) {
        Isolate *isolate = args.GetIsolate();

        const unsigned argc = 1;
        Local<Value> argv[argc] = {args[0]};
        Local<Function> cons = Local<Function>::New(isolate, constructor);
        Local<Object> instance = cons->NewInstance(argc, argv);

        args.GetReturnValue().Set(instance);
    }

    void FloodlightACLRuleWrapper::PackRule(Isolate *isolate, Local<Object>& obj, void *rule) const {
        FloodlightACLRule *r = static_cast<FloodlightACLRule *>(rule);
        obj->Set(String::NewFromUtf8(isolate, "rule-id"), v8::Int32::New(isolate, r->getId()));
        obj->Set(String::NewFromUtf8(isolate, "nw-proto"), v8::Int32::New(isolate, (int) r->getNwProto()));
        obj->Set(String::NewFromUtf8(isolate, "src-ip"),
                 v8::String::NewFromUtf8(isolate, r->getSrcIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "dst-ip"),
                 v8::String::NewFromUtf8(isolate, r->getDstIp().getIp().c_str()));
        obj->Set(String::NewFromUtf8(isolate, "tp-dst"), v8::Int32::New(isolate, (int) r->getTpDst()));
        if (r->getAction() == Rule::Action::ALLOW)
            obj->Set(String::NewFromUtf8(isolate, "action"), v8::String::NewFromUtf8(isolate, "allow"));
        else obj->Set(String::NewFromUtf8(isolate, "action"), v8::String::NewFromUtf8(isolate, "deny"));
    }

    void *FloodlightACLRuleWrapper::UnpackRule(Isolate *isolate, const FunctionCallbackInfo<Value> &args) {
        Handle<Object> ruleObj = Handle<Object>::Cast(args[0]);
        Handle<Value> id = ruleObj->Get(String::NewFromUtf8(isolate, "rule-id"));
        Handle<Value> nwProto = ruleObj->Get(String::NewFromUtf8(isolate, "nw-proto"));
        Handle<Value> srcIp = ruleObj->Get(String::NewFromUtf8(isolate, "src-ip"));
        Handle<Value> dstIp = ruleObj->Get(String::NewFromUtf8(isolate, "dst-ip"));
        Handle<Value> tpDst = ruleObj->Get(String::NewFromUtf8(isolate, "tp-dst"));
        Handle<Value> action = ruleObj->Get(String::NewFromUtf8(isolate, "action"));
        String::Utf8Value(srcIp->ToString());
        Rule *rule = new FloodlightACLRule(
                (short) nwProto->NumberValue(),
                std::string(*(String::Utf8Value(srcIp->ToString()))),
                std::string(*(String::Utf8Value(dstIp->ToString()))),
                (short) tpDst->NumberValue(),
                std::string(*(String::Utf8Value(action->ToString())))
        );
        rule->setId(id->NumberValue());
        return rule;
    }

    void FloodlightACLRuleWrapper::ToString(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        FloodlightACLRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightACLRuleWrapper>(args.Holder());
        args.GetReturnValue().Set(String::NewFromUtf8(isolate, obj->rule->toString().c_str()));
    }

    void FloodlightACLRuleWrapper::GetId(const v8::FunctionCallbackInfo<v8::Value> &args) {
        Isolate* isolate = args.GetIsolate();
        FloodlightACLRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightACLRuleWrapper>(args.Holder());
        args.GetReturnValue().Set(Number::New(isolate, obj->rule->getId()));
    }

    void FloodlightACLRuleWrapper::SetId(const v8::FunctionCallbackInfo<v8::Value> &args) {
        //Isolate* isolate = args.GetIsolate();
        FloodlightACLRuleWrapper* obj = ObjectWrap::Unwrap<FloodlightACLRuleWrapper>(args.Holder());
        int32_t id = args[0]->IsUndefined() ? 0 : args[0]->NumberValue();
        if (id != 0)
            obj->rule->setId(id);
        //todo else...
    }
}
