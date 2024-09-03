#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_QUEUE_SIZE 100
#define TASK_THRESHOLD 10

typedef struct {
    int task_id;
} task_t;

typedef struct {
    task_t tasks[MAX_QUEUE_SIZE];
    int front;
    int rear;
    int size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} task_queue_t;

task_queue_t queue;

void initialize_queue(task_queue_t* q) {
    q->front = 0;
    q->rear = -1;
    q->size = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

int is_queue_empty(task_queue_t* q) {
    return q->size == 0;
}

int is_queue_full(task_queue_t* q) {
    return q->size == MAX_QUEUE_SIZE;
}

void enqueue(task_queue_t* q, task_t task) {
    if (!is_queue_full(q)) {
        q->rear = (q->rear + 1) % MAX_QUEUE_SIZE;
        q->tasks[q->rear] = task;
        q->size++;
    }
}

task_t dequeue(task_queue_t* q) {
    task_t task = {0};
    if (!is_queue_empty(q)) {
        task = q->tasks[q->front];
        q->front = (q->front + 1) % MAX_QUEUE_SIZE;
        q->size--;
    }
    return task;
}

void* worker_thread(void* arg) {
    while (1) {
        pthread_mutex_lock(&queue.mutex);
        while (is_queue_empty(&queue)) {
            pthread_cond_wait(&queue.cond, &queue.mutex);
        }
        
        task_t task = dequeue(&queue);
        pthread_mutex_unlock(&queue.mutex);

        printf("Thread %lu processing task %d\n", pthread_self(), task.task_id);
        sleep(1);
    }
    return NULL;
}

void add_task(task_queue_t* q, task_t task) {
    pthread_mutex_lock(&q->mutex);
    enqueue(q, task);
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

int main() {
    pthread_t threads[MAX_QUEUE_SIZE]; 
    int thread_count = 0;

    initialize_queue(&queue);

    pthread_create(&threads[thread_count++], NULL, worker_thread, NULL);

    for (int i = 1; i <= 8; i++) {
        task_t task = { .task_id = i };
        add_task(&queue, task);
        
        if (queue.size > TASK_THRESHOLD && thread_count < MAX_QUEUE_SIZE) {
            pthread_create(&threads[thread_count++], NULL, worker_thread, NULL);
            printf("Created a new thread to handle the load. Total threads: %d\n", thread_count);
        }

        sleep(0.5);
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
