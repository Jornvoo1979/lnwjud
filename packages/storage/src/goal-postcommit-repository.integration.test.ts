import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GoalContinuationService } from '@lnwjud/application';
import { SqliteDatabase } from './database.js';
import { SqliteGoalRepository } from './goal-repository.js';
import { SqliteGoalPostCommitOutbox } from './goal-postcommit-outbox.js';
import { SqliteWorkspaceRepository } from './workspace-repository.js';

const workspaceId='aabf6b4d-0df9-4461-800e-f9dadddec961';
const actor={clientId:'host-goal-event-test',clientName:'Host Goal Test',sessionId:'test-session'};
describe('Authoritative Goal Repository post-COMMIT events',()=>{
  it('rolls back the new Goal when the trusted outbox cannot stage an event',async()=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'lnwjud-outbox-failure-'));
    const db=new SqliteDatabase(path.join(root,'state.sqlite'));
    try {
      const workspaces=new SqliteWorkspaceRepository(db);
      await workspaces.insert({id:workspaceId,displayName:'Outbox Failure Fixture',rootPath:root,
        realRootPath:root,createdAt:'2026-11-08T10:00:00.000Z'});
      const goals=new SqliteGoalRepository(db);
      let wakeCount=0;
      goals.attachTrustedGoalPostCommitOutbox({
        stage:(): never => {throw new Error('TEST_OUTBOX_INSERT_FAILED');},
      },()=> 'standard',()=>{wakeCount++;});
      const service=new GoalContinuationService(workspaces,goals,{
        now:(): Date => new Date('2026-11-08T10:00:00.000Z'),
      });
      const result=await service.runGoal(actor,{
        workspaceId,goalKey:'outbox-must-not-silently-fail',
        objective:'Verify transaction rollback on outbox failure',
        plan:{steps:[{id:'verify',title:'Verify'}]},leaseSeconds:120,
      });
      expect(result.ok).toBe(false);
      expect(await goals.getByKey(workspaceId,'outbox-must-not-silently-fail')).toBeNull();
      expect(wakeCount).toBe(0);
    }finally{
      db.close();
      await rm(root,{recursive:true,force:true});
    }
  });
  it('rolls back an existing Goal checkpoint if outbox insertion fails',async()=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'lnwjud-checkpoint-failure-'));
    const db=new SqliteDatabase(path.join(root,'state.sqlite'));
    try {
      const workspaces=new SqliteWorkspaceRepository(db);
      await workspaces.insert({id:workspaceId,displayName:'Checkpoint Failure Fixture',rootPath:root,
        realRootPath:root,createdAt:'2026-11-08T10:00:00.000Z'});
      const goals=new SqliteGoalRepository(db);
      const outbox=new SqliteGoalPostCommitOutbox(()=>db.connection);
      outbox.initialize();
      let allowStage=true;
      let wakes=0;
      goals.attachTrustedGoalPostCommitOutbox({
        stage:(transition): string => {
          if(!allowStage)throw new Error('TEST_OUTBOX_INSERT_FAILED');
          return outbox.stage(transition);
        },
      },()=> 'standard',()=>{wakes++;});
      const service=new GoalContinuationService(workspaces,goals,{
        now:(): Date => new Date('2026-11-08T10:00:00.000Z'),
      });
      const created=await service.runGoal(actor,{
        workspaceId,goalKey:'checkpoint-atomic-outbox',
        objective:'Verify existing Goal revision rollback',
        plan:{steps:[{id:'verify',title:'Verify'}]},leaseSeconds:120,
      });
      expect(created.ok).toBe(true);
      if(!created.ok||!created.value.leaseToken)throw Error('Fixture Goal missing');
      const before=await goals.getById(created.value.goalId);
      expect(before?.revision).toBe(0);
      allowStage=false;
      const outcome=await service.checkpointGoal(actor,{
        goalId:created.value.goalId,
        leaseToken:created.value.leaseToken,
        expectedRevision:0,
        currentPhase:'must-not-persist',
        summary:'This checkpoint must roll back',
        stepUpdates:[],nextAction:'Must not be saved',blockers:[],evidence:[],activeTaskIds:[],
      });
      expect(outcome.ok).toBe(false);
      const after=await goals.getById(created.value.goalId);
      expect(after?.revision).toBe(before?.revision);
      expect(after?.currentPhase).toBe(before?.currentPhase);
      expect(outbox.pending(workspaceId)).toHaveLength(1);
      await Promise.resolve();
      expect(wakes).toBe(1);
    }finally{
      db.close();
      await rm(root,{recursive:true,force:true});
    }
  });

  it('persists real revisions, rejects stale CAS and excludes Full Bypass',async()=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'lnwjud-host-event-'));
    const db=new SqliteDatabase(path.join(root,'state.sqlite'));
    try {
      const workspaces=new SqliteWorkspaceRepository(db);
      await workspaces.insert({id:workspaceId,displayName:'Event Fixture',rootPath:root,
        realRootPath:root,createdAt:'2026-11-08T10:00:00.000Z'});
      const goals=new SqliteGoalRepository(db);
      const outbox=new SqliteGoalPostCommitOutbox(()=>db.connection);
      outbox.initialize();
      let fullBypass=false;
      let woke=0;
      goals.attachTrustedGoalPostCommitOutbox(outbox,
        (): 'full_bypass' | 'standard' => fullBypass?'full_bypass':'standard',()=>{woke++;});
      const service=new GoalContinuationService(workspaces,goals,{
        now:(): Date => new Date('2026-11-08T10:00:00.000Z'),
      });
      const created=await service.runGoal(actor,{
        workspaceId,goalKey:'one-real-goal',objective:'Host-committed checkpoint test',
        plan:{steps:[{id:'work',title:'Work'},{id:'done',title:'Done'}]},leaseSeconds:120,
      });
      expect(created.ok).toBe(true);
      if(!created.ok||!created.value.leaseToken)throw Error('Goal missing');
      expect(outbox.pending(workspaceId)).toMatchObject([
        {operation:'run_goal',revision:0,toStatus:'active',fromStatus:null},
      ]);
      const input={
        goalId:created.value.goalId,leaseToken:created.value.leaseToken,
        currentPhase:'progress',summary:'One real checkpoint',
        stepUpdates:[],nextAction:'Next scoped action',blockers:[],
        evidence:[],activeTaskIds:[],
      };
      const committed=await service.checkpointGoal(actor,{...input,expectedRevision:0});
      expect(committed.ok).toBe(true);
      expect(outbox.pending(workspaceId).map(e=>[e.operation,e.revision,e.fromStatus,e.toStatus]))
        .toEqual([['run_goal',0,null,'active'],['checkpoint_goal',1,'active','active']]);
      const stale=await service.checkpointGoal(actor,{...input,expectedRevision:0});
      expect(stale.ok).toBe(false);
      expect(outbox.pending(workspaceId)).toHaveLength(2);
      fullBypass=true;
      const excluded=await service.checkpointGoal(actor,{...input,expectedRevision:1});
      expect(excluded.ok).toBe(true);
      expect(outbox.pending(workspaceId)).toHaveLength(2);
      await Promise.resolve();
      expect(woke).toBeGreaterThan(0);
    }finally{
      db.close();
      await rm(root,{recursive:true,force:true});
    }
  });
});
