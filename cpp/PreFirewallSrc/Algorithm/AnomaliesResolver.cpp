//
// Created by smorzhov on 18.02.16.
//

#include <algorithm>
#include <fstream>
#include "AnomaliesResolver.h"
#include "../Rules/Rule.h"

vector<void *> AnomaliesResolver::findAnomalies(void *rule) {
    oldRules.clear();
    oldRules.push_back(rule);
    for (unsigned int i = 0; i < conflictedRules.size(); ++i) {
        delete (Rule *)conflictedRules[i];
    }
    conflictedRules.clear();
    while (!changes.empty()) {
        delete changes.top();
        changes.pop();
    }
    resolveAnomalies();
    return conflictedRules;
}

void AnomaliesResolver::resolveAnomalies() {
    conflictedRules.clear();
    for (auto r: oldRules) {
        insert(r); //insert into a newRules list
    }
    for (unsigned int i = 0; i < newRules.size(); ++i) {
        Rule *r = static_cast<Rule *>(newRules[i]);
        for (unsigned int j = i + 1; j < newRules.size(); ++j) {
            Rule *s = static_cast<Rule *>(newRules[j]);
            if (r->isSubset(s)) {
                if (r->getAction() == s->getAction() || r->getPriority() > s->getPriority()) {
                    changes.push(new Change(ChangeType::REMOVAL, i, r->clone()));
                    conflictedRules.push_back(r->clone());
                    newRules.erase(newRules.begin() + i);
                    i--;
                }
                break;
            }
        }
    }
}

void AnomaliesResolver::insert(void *rule) {
    Rule *r = static_cast<Rule *>(rule);
    if (newRules.empty()) {
        newRules.push_back(r);
        changes.push(new Change(ChangeType::ADDITION, newRules.size() - 1, nullptr));
    } else {
        bool inserted = false;
        for (unsigned int i = 0; i < newRules.size(); ++i) {
            void *s = newRules[i];
            if (!r->isDisjoint(s))
                inserted = resolve(r, s, i);
            if (inserted) break;
        }
        if (!inserted) {
            newRules.push_back(r);
            changes.push(new Change(ChangeType::ADDITION, newRules.size() - 1, nullptr));
        }
    }
}

bool AnomaliesResolver::resolve(void *rule1, void *rule2, int index) {
    Rule *r = static_cast<Rule *>(rule1);
    Rule *s = static_cast<Rule *>(rule2);
    if (r->equals(s)) {
        if (r->getAction() != s->getAction()) {
            changes.push(new Change(ChangeType::ANOMALY, index, s->clone()));
            conflictedRules.push_back(s->clone());
            s->setAction(Rule::Action::DENY);
        } else {
            //removal (we don't push r into the newRules vector)
            conflictedRules.push_back(s->clone());
        }
        return true;
    }
    if (r->isSubset(s)) {
        if (r->getPriority() != -1 && s->getPriority() != -1 &&
            r->getPriority() > s->getPriority()) {
            //removal (we don't push r into the newRules vector)
            conflictedRules.push_back(s->clone());
            return true;
        }
        changes.push(new Change(ChangeType::ADDITION, index, nullptr));
        newRules.insert(newRules.begin() + index, r);
        return true;
    }
    if (s->isSubset(r)) return false;
    //r and s are correlated
    newRules.push_back(r);
    changes.push(new Change(ChangeType::ADDITION, newRules.size() - 1, nullptr));
    return true;
}

bool AnomaliesResolver::remove(void *rule) {
    auto i = find(newRules.begin(), newRules.end(), rule);
    if (i != newRules.end()) {
        newRules.erase(i);
        return true;
    }
    return false;
}

bool AnomaliesResolver::remove(int64_t id) {
    for (unsigned int i = 0; i < newRules.size(); ++i) {
        if (static_cast<Rule *>(newRules[i])->getId() == id) {
            newRules.erase(newRules.begin() + i);
            return true;
        }
    }
    return false;
}

void AnomaliesResolver::undoChanges() {
    while (!changes.empty()) {
        Change *change = changes.top();
        switch (change->changeType) {
            case ChangeType::ANOMALY:
                newRules[change->index] = static_cast<Rule *>(change->rule)->clone();
                break;
            case ChangeType::ADDITION:
                newRules.erase(newRules.begin() + change->index);
                break;
            case ChangeType::REMOVAL:
                newRules.insert(newRules.begin() + change->index, static_cast<Rule *>(change->rule)->clone());
                break;
        }
        delete changes.top();
        changes.pop();
    }
}

bool AnomaliesResolver::saveChanges(char *fileName) {
    ofstream file;
    file.open(fileName, ios::out | ios::trunc);
    if (!file.is_open())
        return false;
    for (auto r: newRules) {
        file << static_cast<Rule *>(r)->toString();
        file << "\n";
    }
    file.close();
    return true;
}

bool AnomaliesResolver::loadRulesFromFile(char *fileName) {
    ifstream file;
    file.open(fileName, ios::in);
    if (!file.is_open())
        return false;
    string line;
    while (getline(file, line)) {
        //todo
    }
    file.close();
    return true;
}

AnomaliesResolver::~AnomaliesResolver() {
    for (unsigned int i = 0; i < conflictedRules.size(); ++i) {
        delete (Rule *)conflictedRules[i];
    }
    conflictedRules.clear();
    while (!changes.empty()) {
        delete changes.top();
        changes.pop();
    }
    //todo upload changes into a file
/*    for (unsigned int i = 0; i < newRules.size(); ++i) {
        delete (Rule *)newRules[i];
    }*/
    oldRules.clear();
    newRules.clear();
}






