//
// Created by smorzhov on 18.02.16.
//

#pragma once

#include <vector>
#include <stack>
#include <string>
#include <string.h>
#include "../Rules/Rule.h"

using namespace std;

class AnomaliesResolver {
public:
    struct Conflict {
        /**
         * 0 - conflict / the rule wasn't added
         * 1 - was deleted
         */
        int8_t type;
        void * rule;

        Conflict(int8_t type, void *rule) : type(type), rule(rule) { }

        virtual ~Conflict() {
            delete (Rule *) rule;
        }
    };

    const vector<void *> &getNewRules() const { return newRules; }

    //todo в newRules добавить 0 правило, запрещающее все
    AnomaliesResolver() : resolveMode(false) { }

    AnomaliesResolver(const vector<void *> &oldRules) : oldRules(oldRules), resolveMode(false) { }

    void resolveAnomalies();

    vector<Conflict *> findAnomalies(void *);

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
    void *oldRule = 0;
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
    vector<Conflict *> conflictedRules;

    bool resolveMode;
};