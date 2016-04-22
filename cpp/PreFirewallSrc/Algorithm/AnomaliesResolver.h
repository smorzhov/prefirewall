//
// Created by smorzhov on 18.02.16.
//

#pragma once

#include <vector>
#include <stack>
#include <string>
#include <string.h>

using namespace std;

class AnomaliesResolver {
public:
    const vector<void *> &getNewRules() const { return newRules; }

    //todo в newRules добавить 0 правило, запрещающее все
    AnomaliesResolver() : resolveMode(false) { }

    AnomaliesResolver(const vector<void *> &oldRules) : oldRules(oldRules), resolveMode(false) { }

    void resolveAnomalies();

    vector<void *> findAnomalies(void *);

    void undoChanges();

    bool remove(void *);

    bool remove(int64_t);

    bool saveChanges(char *);

    bool loadRulesFromFile(char *);

    virtual ~AnomaliesResolver();

protected:
    void insert(void *);

    /**
    * Resolve anomalies between two oldRules r and s
    */
    bool resolve(void *, void *, int);

private:
    vector<void *> oldRules;
    vector<void *> newRules;

    enum class ChangeType {
        ANOMALY = 0, ADDITION, REMOVAL
    };

    struct Change {
        ChangeType changeType;
        int index;
        void *rule;

        Change(ChangeType changeType, int index, void *rule) : changeType(changeType), index(index),
                                                               rule(rule) { }
    };

    stack<Change *> changes;
    vector<void *> conflictedRules;

    bool resolveMode;
};